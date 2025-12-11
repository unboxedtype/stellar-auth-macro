#![no_std]
#[allow(unused_imports)]
use access_control_macros::{access_control, authorized_by, no_access_control};
use soroban_sdk::{contract, contractimpl, contracttype, Address, Env};

#[contracttype]
pub enum DataKey {
    Counter(Address),
    Owner,      // owner of the program
    SuperOwner, // super admin
}

// Methods that we do not want to be public
#[contract]
pub struct IncrementContract;

impl IncrementContract {
    // Predicate used by #[authorized_by(...)]
    fn only_owner(env: &Env, user: &Address) -> bool {
        let stored: Option<Address> = env.storage().persistent().get(&DataKey::Owner);
        matches!(stored, Some(ref owner) if owner == user)
    }

    fn only_super_owner(env: &Env, user: &Address) -> bool {
        let stored: Option<Address> = env.storage().persistent().get(&DataKey::SuperOwner);
        matches!(stored, Some(ref super_owner) if super_owner == user)
    }
}

#[access_control]
#[contractimpl]
impl IncrementContract {
    // 1) Set owner during deployment/init (one-time).
    #[no_access_control]
    pub fn initialize(env: Env, owner: Address) {
        if env.storage().persistent().has(&DataKey::Owner) {
            panic!("already initialized");
        }
        // Ensure the declared owner actually authorized this init call.
        owner.require_auth();

        env.storage().persistent().set(&DataKey::Owner, &owner);
    }

    #[no_access_control]
    pub fn initialize_super_owner(env: Env, super_owner: Address) {
        if env.storage().persistent().has(&DataKey::SuperOwner) {
            panic!("already initialized");
        }
        // Ensure the declared owner actually authorized this init call.
        super_owner.require_auth();

        env.storage()
            .persistent()
            .set(&DataKey::SuperOwner, &super_owner);
    }

    // Example of a protected method that requires two #[authorized_by] guards to be fulfilled. The macro will inject:
    // i) only_owner(&env, &caller) && caller.require_auth()
    // ii) only_super_owner(&env, &caller) && caller.require_auth()
    #[authorized_by(caller, only_owner)]
    #[authorized_by(caller, only_super_owner)]
    pub fn change_owner(env: Env, caller: Address, new_owner: Address) {
        env.storage().persistent().set(&DataKey::Owner, &new_owner);
    }

    #[no_access_control]
    pub fn increment(env: Env, user: Address, value: u32) -> u32 {
        user.require_auth();
        let key = DataKey::Counter(user.clone());
        let mut count: u32 = env.storage().persistent().get(&key).unwrap_or_default();
        count += value;
        env.storage().persistent().set(&key, &count);
        count
    }

    /// Uses the macro guard: Self::only_owner(&env, &user) + user.require_auth()
    #[authorized_by(user, only_owner)]
    pub fn increment_owner(env: Env, user: Address, value: u32) -> u32 {
        let key = DataKey::Counter(user.clone());
        let mut count: u32 = env
            .storage()
            .persistent()
            .get(&key)
            .unwrap_or_default();
        count += value;
        env.storage().persistent().set(&key, &count);
        count
    }
}

mod test;
