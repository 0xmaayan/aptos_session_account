module deployer::public_key_authenticator {

    use aptos_framework::auth_data::AbstractionAuthData;
    use aptos_framework::bcs_stream::{Self, deserialize_u8};
    use aptos_framework::event;
    use aptos_framework::timestamp;
    use aptos_framework::transaction_context;
    use aptos_framework::string_utils;
    use aptos_framework::big_ordered_map::{Self, BigOrderedMap};
    use aptos_std::ed25519::{
        Self,
        new_signature_from_bytes,
        new_unvalidated_public_key_from_bytes,
        unvalidated_public_key_to_bytes,
    };
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
        public_key: vector<u8>,
    }

    // Resource to store permissions
    struct Permissions has key {
        // The public keys that are permitted
        public_keys_permitted: BigOrderedMap<vector<u8>,PermissionsData>,
    }

    // Resource to store permissions data
    struct PermissionsData has key, copy, drop, store {
        // The functions that are permitted
        functions: vector<String>,
        // The timestamp of the permission, in milliseconds
        timestamp: u64,
    }

    // ====== Authenticator ====== //
    public fun authenticate(
        account: signer,
        auth_data: AbstractionAuthData
    ): signer acquires Permissions {
        let account_addr = signer::address_of(&account);

        // Check if the account has permissions set, if not return error
        assert!(exists<Permissions>(account_addr), E_NO_PERMISSIONS);

        // Get the permissions for the account
        let permissions = borrow_global<Permissions>(account_addr);

        // Extract the public key, signature and digest from the authenticator
        let authenticator = *auth_data.authenticator();
        let stream = bcs_stream::new(authenticator);
        let public_key = new_unvalidated_public_key_from_bytes(
            bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x))
        );
        let signature = new_signature_from_bytes(
            bcs_stream::deserialize_vector<u8>(&mut stream, |x| deserialize_u8(x))
        );
        let digest = *auth_data.digest();

        // Convert the public key to bytes to check if it is permitted
        let public_key_to_bytes = unvalidated_public_key_to_bytes(&public_key);
        let is_public_key_permitted = permissions.public_keys_permitted.contains(&public_key_to_bytes);
        assert!(is_public_key_permitted, E_PUBLIC_KEY_NOT_PERMITTED);

        // Get the public key permissions
        let public_key_permissions = permissions.public_keys_permitted.borrow(&public_key_to_bytes);

        // Check if the permission has expired
        let now: u64 = timestamp::now_seconds();
        assert!(public_key_permissions.timestamp + 60 * 60 > now, E_PERMISSION_EXPIRED);

        // Get the transaction payload
        let txn_payload = transaction_context::entry_function_payload();
        assert!(txn_payload.is_some(), E_NOT_ENTRY_FUNCTION_PAYLOAD);
        let txn_payload = txn_payload.destroy_some();

        // Get the account address
        let account_address = transaction_context::account_address(&txn_payload);

        // Get the module name
        let module_name = transaction_context::module_name(&txn_payload);

        // Get the function name
        let function_name = transaction_context::function_name(&txn_payload);

        
        // Construct the full function that is being called   
        let account_address_formatted = string_utils::to_string_with_canonical_addresses(&account_address).sub_string(1,65);
        let account_addr_str = string::utf8(b"0x");
        account_addr_str.append(account_address_formatted);

        let full_function_identifier = account_addr_str;

        full_function_identifier.append(string::utf8(b"::"));
        full_function_identifier.append(module_name);
        full_function_identifier.append(string::utf8(b"::"));
        full_function_identifier.append(function_name);
      
        // get the permitted functions
        let permitted_functions = public_key_permissions.functions;

        // Check if the function that is being called exists in the permitted functions
        let is_function_permitted = false;
        let i = 0;
        while (i < permitted_functions.length()) {
            if (permitted_functions[i] == full_function_identifier) {
                is_function_permitted = true;
                break;
            };
            i += 1;
        };

        assert!(is_function_permitted, E_FUNCTION_NOT_PERMITTED);

        // Verify the signature
        assert!(ed25519::signature_verify_strict(&signature, &public_key, digest), E_INVALID_SIGNATURE);
 
        account
    }
 
    // ====== Core Functionality ====== //
 
    public entry fun permit_public_key(
        signer: &signer,
        public_key: vector<u8>,
        permitted_functions: vector<String>
    ) acquires Permissions {
        let account_addr = signer::address_of(signer);
        assert!(public_key.length() == 32, E_INVALID_PUBLIC_KEY);
        
        // Check if Permissions resource exists, if not create it
        if (!exists<Permissions>(account_addr)) {
            let permissions = Permissions {
                public_keys_permitted: big_ordered_map::new_with_config(
                    64,32,true
                ),
            };
            move_to(signer, permissions);
        };

        // check if the functions is not empty
        assert!(permitted_functions.length() > 0, E_NO_FUNCTIONS);

        // permit public key
        let permissions = borrow_global_mut<Permissions>(account_addr);
        let timestamp = timestamp::now_seconds() + 60 * 60; // 1 hour

        permissions.public_keys_permitted.add(public_key, PermissionsData {
            functions: permitted_functions,
            timestamp,
        });

        event::emit(PermissionGranted {
            account: account_addr,
            public_key,
            functions: permitted_functions,
            timestamp,
        });
    }
 
    public entry fun revoke_permission(
        signer: &signer,
        public_key: vector<u8>,
    ) acquires Permissions {
        let account_addr = signer::address_of(signer);
        
        assert!(exists<Permissions>(account_addr), E_NO_PERMISSIONS);
 
        // remove public key
        let permissions = borrow_global_mut<Permissions>(account_addr);
        permissions.public_keys_permitted.remove(&public_key);

        event::emit(PermissionRevoked {
            account: account_addr,
            public_key,
        });
    }

    // View functions
    #[view]
    public fun get_permissions(account_addr: address, public_key: vector<u8>): PermissionsData acquires Permissions {
        if (exists<Permissions>(account_addr)) {
            let permissions = borrow_global_mut<Permissions>(account_addr);
            let public_key_permit = permissions.public_keys_permitted.contains(&public_key);
            if(public_key_permit == false) {
                PermissionsData {
                    functions: vector::empty(),
                    timestamp: 0,
                }
            }else{
                let public_key_permit = permissions.public_keys_permitted.borrow(&public_key);
                *public_key_permit
            }
        } else {
            PermissionsData {
                functions: vector::empty(),
                timestamp: 0,
            }
        }
    }
} 