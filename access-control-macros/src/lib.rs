//! Proc macros:
//! - #[access_control] on an `impl` block:
//!     * Finds and consumes every `#[authorized_by(arg_ident, check_fn_or_path)]` on each method,
//!       then injects a single combined guard at the top of the method body. All predicates are
//!       ANDed together and, if they pass, each subject gets `require_auth()` before the original body.
//!     * Enforces policy: every public method must have **either** `#[no_access_control]` **or**
//!       one-or-more `#[authorized_by(..)]`. Mixing both on the same method is an error.
//!     * Detects “public” as: trait impl methods, `#[contractimpl]` methods, or methods with `pub` visibility.
//!     * Uses hybrid `Env` resolution (prefer a parameter named `env`, else a unique `Env`-typed param).
//!
//! - #[no_access_control] on a function:
//!     * Marker (no-op) indicating the method is intentionally open (no guard injected).
//!
//! - #[authorized_by(arg_ident, check_fn_or_path)] on a function:
//!     * Syntax-only attribute when used standalone (left in place); instrumentation is performed
//!       locally by `#[access_control]` so expansion order with other macros stays predictable.

extern crate proc_macro;

use proc_macro::TokenStream;
use proc_macro2::{Span, TokenStream as TokenStream2};
use quote::quote;
use std::collections::BTreeSet;
use syn::{
    parse::{Parse, ParseStream},
    spanned::Spanned,
    Attribute, FnArg, ImplItem, ItemImpl, Meta, Pat, Path, Token, Type, Visibility,
};

use proc_macro_error::{abort, abort_if_dirty, emit_error, emit_warning, proc_macro_error};

fn has_no_access_attr(attrs: &[Attribute]) -> bool {
    attrs.iter().any(|a| a.path().is_ident("no_access_control"))
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn no_access_control(_attr: TokenStream, item: TokenStream) -> TokenStream {
    item
}

struct AuthorizedArgs {
    arg: syn::Ident,
    check_fn: Path,
}

/// The parser enforces the format: `<ident> , <path>`.
impl Parse for AuthorizedArgs {
    fn parse(input: ParseStream) -> syn::Result<Self> {
        let arg: syn::Ident = input.parse()?;
        input.parse::<Token![,]>()?;
        let check_fn: Path = input.parse()?;
        Ok(Self { arg, check_fn })
    }
}

/// Iterates over the function signature's arguments and returns the "desired" parameter, if it exists.
fn find_param_ident(sig: &syn::Signature, desired: &str) -> Option<syn::Ident> {
    sig.inputs.iter().find_map(|arg| match arg {
        FnArg::Typed(pat_ty) => match &*pat_ty.pat {
            Pat::Ident(p) if p.ident == desired => Some(p.ident.clone()),
            _ => None,
        },
        FnArg::Receiver(_) => None, // skip for 'self'
    })
}

/// Return the parameter identifiers whose *spelled* type is `Env` (or `&Env`, or `soroban_sdk::Env`).
fn env_type_candidates(sig: &syn::Signature) -> Vec<syn::Ident> {
    let mut out = Vec::new();
    for arg in &sig.inputs {
        let FnArg::Typed(pat_ty) = arg else { continue };
        let Pat::Ident(pat_ident) = &*pat_ty.pat else {
            continue;
        };

        // peel references like &Env
        let mut ty: &Type = &*pat_ty.ty;
        if let Type::Reference(r) = ty {
            ty = &*r.elem;
        }
        if let Type::Path(p) = ty {
            if let Some(seg) = p.path.segments.last() {
                if seg.ident == "Env" {
                    out.push(pat_ident.ident.clone());
                }
            }
        }
    }
    out
}

/// Env resolution:
///  1) The variable must have name `env`
///  2) Its type has to be `Env` or `&Env` or `&soroban_sdk::Env`
/// If no such variable is found, return None

fn find_env_ident_hybrid(sig: &syn::Signature) -> Option<syn::Ident> {
    if let Some(id) = find_param_ident(sig, "env") {
        let cands = env_type_candidates(sig);
        if cands.len() == 1 && cands[0] == id {
            Ok(id)
        } else {
            None
        }
    } else {
        None
    }
}

/// Builds a new function body that enforces every `#[authorized_by(...)]` guard on the target
/// All predicates are evaluated together, and if any predicate returns `false`, the call panics as unauthorized.
/// After the combined checks pass, `require_auth()` is invoked for each distinct address, and then the
/// original body is executed unchanged.
fn instrument_block_multi(
    body: &syn::Block,
    pairs: &[(TokenStream2, syn::Ident)], // (call_path, arg_ident)
    env_ident: &syn::Ident,
    span: Span,
) -> Box<syn::Block> {
    // Iterate through the auth_pairs and build check1(&env, &a1) && check2(&env, &a2) && ...
    let checks = pairs.iter().map(|(call_path, arg)| {
        quote! { #call_path(&#env_ident, &#arg) }
    });

    // Iterate and build a1.require_auth(); a2.require_auth(); ...
    // Also dedupe calls for require_auth on addresses featuring multiple times in `auths`.
    let mut seen = BTreeSet::<String>::new();
    let auths = pairs.iter().filter_map(|(_, arg)| {
        let k = arg.to_string();
        if seen.insert(k) {
            Some(quote! { #arg.require_auth(); })
        } else {
            None
        }
    });

    syn::parse_quote_spanned! { span =>
        {
            if !(true #(&& (#checks))* ) {
                ::core::panic!("unauthorized: one or more authorization predicates failed");
            }
            #(#auths)*
            #body
        }
    }
}

/// 1) Finds and removes the instances of #[authorized_by(...)] in attrs,
/// 2) parses it into AuthorizedArgs and pushes it to the output vector,
/// 3) returns the output vector contained the authorizaed args (or None if malformed attr).
fn take_all_authorized_args(attrs: &mut Vec<Attribute>) -> Vec<AuthorizedArgs> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < attrs.len() {
        if attrs[i].path().is_ident("authorized_by") {
            let attr = attrs.remove(i);
            match attr.meta {
                Meta::List(_) => match attr.parse_args::<AuthorizedArgs>() {
                    Ok(a) => out.push(a),
                    Err(e) => {
                        emit_error!(attr.span(), "malformed #[authorized_by(...)] args: {}", e);
                    }
                },
                _ => {
                    emit_error!(
                        attr.span(),
                        "#[authorized_by] must be written as #[authorized_by(arg_ident, path)]"
                    );
                }
            }
            // do not i += 1 here because we just removed current slot
        } else {
            i += 1;
        }
    }
    out
}

fn build_call_path(check_fn: &Path, use_self: bool) -> TokenStream2 {
    if use_self && check_fn.segments.len() == 1 {
        let ident = &check_fn.segments[0].ident;
        quote! { Self::#ident }
    } else {
        let p = check_fn;
        quote! { #p }
    }
}

fn get_env_ident_or_warn(sig: &syn::Signature, fn_name: &syn::Ident) -> Option<syn::Ident> {
    if let Some(id) = find_env_ident_hybrid(sig) {
        return Some(id);
    }
    let cands = env_type_candidates(sig);
    if cands.len() > 1 {
        emit_warning!(
            sig.span(),
            "skipping #[authorized_by]: multiple `Env`-typed parameters on `{}`; \
             please name the desired one `env`",
            fn_name
        );
    } else {
        emit_warning!(
            sig.span(),
            "skipping #[authorized_by]: no `Env` parameter found on `{}`; leaving unchanged",
            fn_name
        );
    }
    None
}

/// Returns true if desired parameter exists within the function signature otherwise emits a warning and returns false.
fn ensure_param_or_warn(sig: &syn::Signature, fn_name: &syn::Ident, desired: &syn::Ident) -> bool {
    if find_param_ident(sig, &desired.to_string()).is_some() {
        return true;
    }
    emit_warning!(
        desired.span(),
        "skipping #[authorized_by]: parameter `{}` not found on `{}` (generated wrapper?)",
        desired,
        fn_name
    );

    false
}

fn instrument_impl_like_multi(
    sig: &syn::Signature,
    block: &mut syn::Block,
    fn_name: &syn::Ident,
    args_list: &[AuthorizedArgs],
    use_self: bool,
) -> bool {
    if args_list.is_empty() {
        return false;
    }

    // Ensure each named param exists; if any missing, skip entirely (warned inside).
    for args in args_list {
        if !ensure_param_or_warn(sig, fn_name, &args.arg) {
            return false;
        }
    }

    // Resolve Env once.
    let env_ident = match get_env_ident_or_warn(sig, fn_name) {
        Some(e) => e,
        None => return false,
    };

    // Build (call_path, arg_ident) pairs.
    let pairs: Vec<(TokenStream2, syn::Ident)> = args_list
        .iter()
        .map(|a| (build_call_path(&a.check_fn, use_self), a.arg.clone()))
        .collect();

    let body = &*block; // borrow before replace
    *block = *instrument_block_multi(body, &pairs, &env_ident, sig.span());
    true
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn authorized_by(attr: TokenStream, item: TokenStream) -> TokenStream {
    // Validate syntax but do not instrument here. This is because when evaluating multiple authorized_by attributes
    // it can cause issues of double instrumentation when #[access_control] processes it later. To avoid any ugly errors
    // and enforced policies in a single location, the macro instrumentation is uniformly handled through access_control
    if let Err(e) = syn::parse::<AuthorizedArgs>(attr) {
        emit_error!(e.span(), "malformed #[authorized_by(..)]: {}", e);
    }
    item
}

#[proc_macro_error]
#[proc_macro_attribute]
pub fn access_control(_attr: TokenStream, item: TokenStream) -> TokenStream {
    if let Ok(mut impl_block) = syn::parse::<ItemImpl>(item.clone()) {
        for it in &mut impl_block.items {
            if let ImplItem::Fn(m) = it {
                // Pull out *all* authorized_by(...) attributes now
                let auth_args = take_all_authorized_args(&mut m.attrs);
                let has_no_access = has_no_access_attr(&m.attrs);

                // Enforce either ONLY #[no_access_control], or one-or-more #[authorized_by(..)]
                if has_no_access && !auth_args.is_empty() {
                    emit_error!(
                        m.sig.ident.span(),
                        "cannot combine #[no_access_control] with #[authorized_by(..)] on `{}`; \
                         use one or the other",
                        m.sig.ident
                    );
                }

                // If we have any authorized_by(..), instrument with *all* predicates
                let mut had_authorized = false;
                if !auth_args.is_empty() {
                    if instrument_impl_like_multi(
                        &m.sig,
                        &mut m.block,
                        &m.sig.ident,
                        &auth_args,
                        true,
                    ) {
                        had_authorized = true;
                    }
                }

                // Public-surface detection (trait impl, contractimpl, or explicit pub)
                let is_trait_impl = impl_block.trait_.is_some();
                let has_contractimpl_attr = impl_block
                    .attrs
                    .iter()
                    .any(|a| a.path().is_ident("contractimpl"));
                let is_public = is_trait_impl
                    || has_contractimpl_attr
                    || !matches!(m.vis, Visibility::Inherited);

                // Enforce that every public fn is either open or protected
                if is_public && !(had_authorized || has_no_access) {
                    emit_error!(
                        m.sig.ident.span(),
                        "public method {} is missing #[no_access_control] or #[authorized_by(...)]",
                        m.sig.ident
                    );
                }
            }
        }
        abort_if_dirty();
        return TokenStream::from(quote!(#impl_block));
    }

    abort!(
        Span::call_site(),
        "#[access_control] must be placed on an `impl` block."
    );
}
