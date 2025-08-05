module deployer::public_key_authenticator {

    use aptos_framework::auth_data::{Self, AbstractionAuthData};
    use aptos_framework::bcs_stream::{Self, deserialize_u8};
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use aptos_framework::transaction_context;
    use aptos_framework::string_utils;
    use aptos_std::ed25519::{
        Self,
        new_signature_from_bytes,
        new_unvalidated_public_key_from_bytes,
    };
    use std::option::{Self, Option};
    use std::vector;
    use std::signer;
    use std::string::{Self, String};

    // Error codes
    /// Invalid public key format
    const E_INVALID_PUBLIC_KEY: u64 = 1;
    /// Authenticator not found
    const E_AUTHENTICATOR_NOT_FOUND: u64 = 2;
    /// Unauthorized access
    const E_UNAUTHORIZED: u64 = 3;
    /// Public key not permitted
    const E_PUBLIC_KEY_NOT_PERMITTED: u64 = 4;
    /// No permissions
    const E_NO_PERMISSIONS: u64 = 5;
    /// Invalid signature
    const E_INVALID_SIGNATURE: u64 = 6;
    /// Permission expired
    const E_PERMISSION_EXPIRED: u64 = 7;
    /// Not an entry function payload
    const E_NOT_ENTRY_FUNCTION_PAYLOAD: u64 = 8;
    /// Need to define at least one function to permit
    const E_NO_FUNCTIONS: u64 = 9;
    /// Function not permitted
    const E_FUNCTION_NOT_PERMITTED: u64 = 10;

    // Events
    #[event]
    struct PermissionGranted has drop, store {
        account: address,
        public_key: vector<u8>,
        functions: vector<String>,
        timestamp: u64,
    }

    #[event]
    struct PermissionRevoked has drop, store {
        account: address,
    }

    // Resource to store public key authenticator data
    struct PublicKeyPermissions has key, copy, drop {
        // The public key that is permitted
        public_key_permitted: Option<vector<u8>>,
        // The functions that are permitted
        functions: vector<String>,
        // The timestamp of the permission, in milliseconds
        timestamp: u64,
    }

    // ====== Authenticator ====== //
    public fun authenticate(
        account: signer,
        auth_data: AbstractionAuthData
    ): signer acquires PublicKeyPermissions {
        let account_addr = signer::address_of(&account);
        assert!(exists<PublicKeyPermissions>(account_addr), E_NO_PERMISSIONS);

        // Check if a public key is permitted
        let permissions = borrow_global<PublicKeyPermissions>(account_addr);
        assert!(permissions.public_key_permitted.is_some(), E_PUBLIC_KEY_NOT_PERMITTED);

        // Check if the permission has expired
        let now: u64 = timestamp::now_seconds();
        assert!(permissions.timestamp + 60 * 60 > now, E_PERMISSION_EXPIRED);

        let txn_payload = transaction_context::entry_function_payload();
        assert!(txn_payload.is_some(), E_NOT_ENTRY_FUNCTION_PAYLOAD);
        // get the transaction payload
        let txn_payload = txn_payload.destroy_some();
        let account_address = transaction_context::account_address(&txn_payload);
        
        let module_name = transaction_context::module_name(&txn_payload);

        let function_name = transaction_context::function_name(&txn_payload);

        // get the permitted functions
        let permitted_functions = permissions.functions;

        // check if the transaction is permitted
        let is_permitted = false;
        
        // Construct the full function identifier        
        let account_address_formatted = string_utils::to_string_with_canonical_addresses(&account_address).sub_string(1,65);
        let account_addr_str = string::utf8(b"0x");
        account_addr_str.append(account_address_formatted);

        let full_function_identifier = account_addr_str;

        string::append(&mut full_function_identifier, string::utf8(b"::"));
        string::append(&mut full_function_identifier, module_name);
        string::append(&mut full_function_identifier, string::utf8(b"::"));
        string::append(&mut full_function_identifier, function_name);
      
        
        // Check if this identifier exists in the permitted functions
        let i = 0;
        while (i < vector::length(&permitted_functions)) {
            if (permitted_functions[i] == full_function_identifier) {
                is_permitted = true;
                break;
            };
            i = i + 1;
        };
        assert!(is_permitted, E_FUNCTION_NOT_PERMITTED);

        // Extract the public key and signature from the authenticator
        let authenticator = *auth_data::authenticator(&auth_data);
        let stream = bcs_stream::new(authenticator);
        let public_key = new_unvalidated_public_key_from_bytes(
            bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x))
        );
        let signature = new_signature_from_bytes(
            bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x))
        );

        // Verify the signature
        let digest = *auth_data::digest(&auth_data);
        assert!(ed25519::signature_verify_strict(&signature, &public_key, digest), E_INVALID_SIGNATURE);
 
        account
    }
 
    // ====== Core Functionality ====== //
 
    public entry fun permit_public_key(
        signer: &signer,
        public_key: vector<u8>,
        permitted_functions: vector<String>
    ) acquires PublicKeyPermissions {
        let account_addr = signer::address_of(signer);
        assert!(std::vector::length(&public_key) == 32, E_INVALID_PUBLIC_KEY);
        
        // Check if PublicKeyPermissions resource exists, if not create it
        if (!exists<PublicKeyPermissions>(account_addr)) {
            let permissions = PublicKeyPermissions {
                public_key_permitted: option::none(),
                functions: vector::empty(),
                timestamp: 0,
            };
            move_to(signer, permissions);
        };

        // check if the functions is not empty
        assert!(std::vector::length(&permitted_functions) > 0, E_NO_FUNCTIONS);

        // permit public key
        let permissions = borrow_global_mut<PublicKeyPermissions>(account_addr);
        permissions.public_key_permitted = option::some(public_key);
        let permit_time = timestamp::now_seconds() + 60 * 60; // 1 hour
        permissions.timestamp = permit_time;
        permissions.functions = permitted_functions;

        event::emit(PermissionGranted {
            account: account_addr,
            public_key: public_key,
            timestamp: permit_time,
            functions: permitted_functions,
        });
    }
 
    public entry fun revoke_permission(
        signer: &signer,
    ) acquires PublicKeyPermissions {
        let account_addr = signer::address_of(signer);
        
        assert!(exists<PublicKeyPermissions>(account_addr), E_NO_PERMISSIONS);
 
        // remove public key
        let permissions = borrow_global_mut<PublicKeyPermissions>(account_addr);
        permissions.public_key_permitted = option::none();
        permissions.timestamp = 0;
        permissions.functions = vector::empty();

        event::emit(PermissionRevoked {
            account: account_addr,
        });
    }

    // View functions
    #[view]
    public fun get_permitted_public_key(account_addr: address): PublicKeyPermissions acquires PublicKeyPermissions {
        if (!exists<PublicKeyPermissions>(account_addr)) {
            PublicKeyPermissions {
                public_key_permitted: option::none(),
                functions: vector::empty(),
                timestamp: 0,
            }
        } else {
            let permissions = borrow_global<PublicKeyPermissions>(account_addr);
            *permissions
        }
    }
} 