#[cfg(feature = "software_realm_tests")]
mod software_realm {
    use juicebox_sdk::{AuthToken, RealmId, RecoverError, TokioSleeper, *};
    use juicebox_sdk_networking::reqwest;
    use juicebox_sdk_networking::rpc::LoadBalancerService;
    use juicebox_sdk_process_group::ProcessGroup;
    use juicebox_sdk_realm_auth::{creation::create_token, AuthKey, AuthKeyVersion, Claims};
    use juicebox_sdk_software_realm::{Runner, RunnerArgs};
    use rand::distributions::Alphanumeric;
    use rand::rngs::OsRng;
    use rand::Rng;
    use std::collections::HashMap;
    use std::str::FromStr;
    use url::Url;

    async fn create_realm(pg: &mut ProcessGroup) -> (AuthToken, Realm) {
        let id = RealmId::new_random(&mut OsRng);
        let port: u16 = OsRng.gen_range(10000..=65535);

        let auth_key: String = OsRng
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        let issuer: String = OsRng
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();
        let subject: String = OsRng
            .sample_iter(&Alphanumeric)
            .take(32)
            .map(char::from)
            .collect();

        Runner::run(
            pg,
            &RunnerArgs {
                id,
                port,
                secrets: HashMap::from([(issuer.clone(), HashMap::from([(1, auth_key.clone())]))]),
            },
        )
        .await;

        let token = create_token(
            &Claims {
                issuer,
                subject,
                audience: id,
            },
            &AuthKey::from(auth_key.into_bytes()),
            AuthKeyVersion(1),
        );

        (
            token,
            Realm {
                id,
                address: Url::from_str(&format!("http://0.0.0.0:{}", port)).unwrap(),
                public_key: None,
            },
        )
    }

    async fn create_realms(
        count: u8,
        pg: &mut ProcessGroup,
    ) -> (Vec<Realm>, HashMap<RealmId, AuthToken>) {
        let mut realms: Vec<Realm> = vec![];
        let mut tokens: HashMap<RealmId, AuthToken> = HashMap::new();

        for _ in 0..count {
            let (token, realm) = create_realm(pg).await;
            realms.push(realm.to_owned());
            tokens.insert(realm.id, token);
        }

        (realms, tokens)
    }

    async fn create_client(
        realm_count: u8,
        pg: &mut ProcessGroup,
    ) -> Client<TokioSleeper, reqwest::Client<LoadBalancerService>, HashMap<RealmId, AuthToken>>
    {
        let (realms, tokens) = create_realms(realm_count, pg).await;

        let configuration = Configuration {
            realms,
            register_threshold: realm_count,
            recover_threshold: realm_count,
            pin_hashing_mode: PinHashingMode::FastInsecure,
        };

        ClientBuilder::new()
            .tokio_sleeper()
            .reqwest()
            .configuration(configuration)
            .auth_token_manager(tokens)
            .build()
    }

    #[tokio::test]
    async fn register() {
        let mut process_group = ProcessGroup::new();
        let client = create_client(1, &mut process_group).await;

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 2 })
            .await
            .expect("register failed");
    }

    #[tokio::test]
    async fn recover_not_registered() {
        let mut process_group = ProcessGroup::new();
        let client = create_client(1, &mut process_group).await;

        let pin = Pin::from(b"1234".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        match client.recover(&pin, &user_info).await {
            Err(RecoverError::NotRegistered) => {}
            result => panic!("Unexpected result from recover: {result:?}"),
        };
    }

    #[tokio::test]
    async fn delete() {
        let mut process_group = ProcessGroup::new();
        let client = create_client(1, &mut process_group).await;

        client.delete().await.expect("delete failed");
    }

    /// Register on 4 out of 4 realms and recover from all 4.
    #[tokio::test]
    async fn register_and_recover() {
        let mut process_group = ProcessGroup::new();
        let client = create_client(4, &mut process_group).await;

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 2 })
            .await
            .expect("register failed");

        let recovered_secret = client
            .recover(&pin, &user_info)
            .await
            .expect("recover failed");

        assert_eq!(secret.expose_secret(), recovered_secret.expose_secret());
    }

    /// Register on 3 out of 4 realms, and then recover from 4 with a threshold of 3.
    #[tokio::test]
    async fn partial_register_and_recover() {
        let mut process_group = ProcessGroup::new();
        let (mut realms, mut tokens) = create_realms(3, &mut process_group).await;

        let fake_realm_id = RealmId::new_random(&mut OsRng);
        realms.push(Realm {
            id: fake_realm_id,
            address: Url::from_str("http://0.0.0.0:0").unwrap(),
            public_key: None,
        });
        tokens.insert(fake_realm_id, AuthToken::from("a.b.c".to_string()));

        let configuration = Configuration {
            realms,
            register_threshold: 3,
            recover_threshold: 3,
            pin_hashing_mode: PinHashingMode::FastInsecure,
        };
        let client = ClientBuilder::new()
            .tokio_sleeper()
            .reqwest()
            .configuration(configuration)
            .auth_token_manager(tokens)
            .build();

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 2 })
            .await
            .expect("register failed");

        let recovered_secret = client
            .recover(&pin, &user_info)
            .await
            .expect("recover failed");

        assert_eq!(secret.expose_secret(), recovered_secret.expose_secret());
    }

    /// Register on 2 out of 4 realms, and then attempt recovery from 4 with a threshold of 3.
    #[tokio::test]
    async fn partial_register_and_recover_failure() {
        let mut process_group = ProcessGroup::new();
        let (realms, tokens) = create_realms(4, &mut process_group).await;

        let register_configuration = Configuration {
            realms: realms[0..2].to_vec(),
            register_threshold: 2,
            recover_threshold: 2,
            pin_hashing_mode: PinHashingMode::FastInsecure,
        };
        let register_client = ClientBuilder::new()
            .tokio_sleeper()
            .reqwest()
            .configuration(register_configuration)
            .auth_token_manager(tokens.clone())
            .build();

        let recover_configuration = Configuration {
            realms,
            register_threshold: 3,
            recover_threshold: 3,
            pin_hashing_mode: PinHashingMode::FastInsecure,
        };
        let recover_client = ClientBuilder::new()
            .tokio_sleeper()
            .reqwest()
            .configuration(recover_configuration)
            .auth_token_manager(tokens)
            .build();

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        register_client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 2 })
            .await
            .expect("register failed");

        match recover_client.recover(&pin, &user_info).await {
            Err(RecoverError::NotRegistered) => {}
            result => panic!("Unexpected result from recover: {result:?}"),
        };
    }

    #[tokio::test]
    async fn register_and_recover_with_wrong_pin() {
        let mut process_group = ProcessGroup::new();
        let client = create_client(4, &mut process_group).await;

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 2 })
            .await
            .expect("register failed");

        let recovered_secret = client
            .recover(&pin, &user_info)
            .await
            .expect("recover failed");

        assert_eq!(secret.expose_secret(), recovered_secret.expose_secret());

        match client
            .recover(&Pin::from(b"abcd".to_vec()), &user_info)
            .await
        {
            Err(RecoverError::InvalidPin { guesses_remaining }) => {
                assert_eq!(guesses_remaining, 1);
            }
            result => panic!("Unexpected result from recover: {result:?}"),
        };
    }

    #[tokio::test]
    async fn register_and_recover_with_wrong_user_info() {
        let mut process_group = ProcessGroup::new();
        let client = create_client(4, &mut process_group).await;

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 2 })
            .await
            .expect("register failed");

        let recovered_secret = client
            .recover(&pin, &user_info)
            .await
            .expect("recover failed");

        assert_eq!(secret.expose_secret(), recovered_secret.expose_secret());

        match client
            .recover(&pin, &UserInfo::from(b"nope".to_vec()))
            .await
        {
            Err(RecoverError::InvalidPin { guesses_remaining }) => {
                assert_eq!(guesses_remaining, 1);
            }
            result => panic!("Unexpected result from recover: {result:?}"),
        };
    }

    #[tokio::test]
    async fn register_and_recover_from_previous_configuration() {
        let mut process_group = ProcessGroup::new();
        let (previous_realms, previous_tokens) = create_realms(2, &mut process_group).await;
        let (current_realms, mut current_tokens) = create_realms(4, &mut process_group).await;
        current_tokens.extend(previous_tokens.clone().into_iter());

        let previous_configuration = Configuration {
            realms: previous_realms,
            register_threshold: 2,
            recover_threshold: 2,
            pin_hashing_mode: PinHashingMode::FastInsecure,
        };
        let previous_client = ClientBuilder::new()
            .tokio_sleeper()
            .reqwest()
            .configuration(previous_configuration.clone())
            .auth_token_manager(previous_tokens)
            .build();

        let configuration = Configuration {
            realms: current_realms,
            register_threshold: 3,
            recover_threshold: 3,
            pin_hashing_mode: PinHashingMode::FastInsecure,
        };
        let current_client = ClientBuilder::new()
            .tokio_sleeper()
            .reqwest()
            .configuration(configuration)
            .previous_configurations(vec![previous_configuration])
            .auth_token_manager(current_tokens)
            .build();

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        previous_client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 2 })
            .await
            .expect("register failed");

        let recovered_secret = current_client
            .recover(&pin, &user_info)
            .await
            .expect("recover failed");
        assert_eq!(recovered_secret.expose_secret(), secret.expose_secret());
    }

    #[tokio::test]
    async fn recover_after_delete() {
        let mut process_group = ProcessGroup::new();
        let client = create_client(4, &mut process_group).await;

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 2 })
            .await
            .expect("register failed");

        let recovered_secret = client
            .recover(&pin, &user_info)
            .await
            .expect("recover failed");

        assert_eq!(secret.expose_secret(), recovered_secret.expose_secret());

        client.delete().await.expect("delete failed");

        match client.recover(&pin, &user_info).await {
            Err(RecoverError::NotRegistered) => {}
            result => panic!("Unexpected result from recover: {result:?}"),
        };
    }

    #[tokio::test]
    async fn recover_after_failed_recovery_with_guesses_remaining() {
        let mut process_group = ProcessGroup::new();
        let client = create_client(4, &mut process_group).await;

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 2 })
            .await
            .expect("register failed");

        match client
            .recover(&Pin::from(b"nope".to_vec()), &user_info)
            .await
        {
            Err(RecoverError::InvalidPin { guesses_remaining }) => {
                assert_eq!(guesses_remaining, 1);
            }
            result => panic!("Unexpected result from recover: {result:?}"),
        };

        let recovered_secret = client
            .recover(&pin, &user_info)
            .await
            .expect("recover failed");

        assert_eq!(secret.expose_secret(), recovered_secret.expose_secret());
    }

    #[tokio::test]
    async fn recover_after_failed_recovery_without_guesses_remaining() {
        let mut process_group = ProcessGroup::new();
        let client = create_client(4, &mut process_group).await;

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 1 })
            .await
            .expect("register failed");

        match client
            .recover(&Pin::from(b"nope".to_vec()), &user_info)
            .await
        {
            Err(RecoverError::InvalidPin { guesses_remaining }) => {
                assert_eq!(guesses_remaining, 0);
            }
            result => panic!("Unexpected result from recover: {result:?}"),
        };

        match client.recover(&pin, &user_info).await {
            Err(RecoverError::InvalidPin { guesses_remaining }) => {
                assert_eq!(guesses_remaining, 0);
            }
            result => panic!("Unexpected result from recover: {result:?}"),
        };
    }

    #[tokio::test]
    async fn register_with_not_enough_threshold() {
        let mut process_group = ProcessGroup::new();
        let (mut realms, mut tokens) = create_realms(4, &mut process_group).await;

        let fake_realm_id = RealmId::new_random(&mut OsRng);
        realms.push(Realm {
            id: fake_realm_id,
            address: Url::from_str("http://0.0.0.0:0").unwrap(),
            public_key: None,
        });
        tokens.insert(fake_realm_id, AuthToken::from("a.b.c".to_string()));

        let configuration = Configuration {
            realms,
            register_threshold: 5,
            recover_threshold: 5,
            pin_hashing_mode: PinHashingMode::FastInsecure,
        };

        let client = ClientBuilder::new()
            .tokio_sleeper()
            .reqwest()
            .configuration(configuration)
            .auth_token_manager(tokens)
            .build();

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        match client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 1 })
            .await
        {
            Err(RegisterError::Transient) => {}
            result => panic!("Unexpected result from register: {result:?}"),
        };
    }

    #[tokio::test]
    async fn register_with_invalid_auth() {
        let mut process_group = ProcessGroup::new();
        let (realms, mut tokens) = create_realms(4, &mut process_group).await;
        *tokens.get_mut(&realms.iter().next().unwrap().id).unwrap() =
            AuthToken::from("a.b.c".to_string());

        let configuration = Configuration {
            realms,
            register_threshold: 4,
            recover_threshold: 4,
            pin_hashing_mode: PinHashingMode::FastInsecure,
        };

        let client = ClientBuilder::new()
            .tokio_sleeper()
            .reqwest()
            .configuration(configuration)
            .auth_token_manager(tokens)
            .build();

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        match client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 1 })
            .await
        {
            Err(RegisterError::InvalidAuth) => {}
            result => panic!("Unexpected result from register: {result:?}"),
        };
    }

    #[tokio::test]
    async fn complex_register_recover_delete() {
        let mut process_group = ProcessGroup::new();
        let client = create_client(10, &mut process_group).await;

        let pin = Pin::from(b"1234".to_vec());
        let secret = UserSecret::from(b"artemis".to_vec());
        let user_info = UserInfo::from(b"apollo".to_vec());

        client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 2 })
            .await
            .expect("register failed");

        match client
            .recover(&Pin::from(b"1212".to_vec()), &user_info)
            .await
        {
            Err(RecoverError::InvalidPin { guesses_remaining }) => {
                assert_eq!(guesses_remaining, 1);
            }
            result => panic!("Unexpected result from recover: {result:?}"),
        };

        let recovered_secret = client
            .recover(&pin, &user_info)
            .await
            .expect("recover failed");
        assert_eq!(secret.expose_secret(), recovered_secret.expose_secret());

        match client
            .recover(&Pin::from(b"1212".to_vec()), &user_info)
            .await
        {
            Err(RecoverError::InvalidPin { guesses_remaining }) => {
                assert_eq!(guesses_remaining, 1);
            }
            result => panic!("Unexpected result from recover: {result:?}"),
        };

        match client
            .recover(&Pin::from(b"1212".to_vec()), &user_info)
            .await
        {
            Err(RecoverError::InvalidPin { guesses_remaining }) => {
                assert_eq!(guesses_remaining, 0);
            }
            result => panic!("Unexpected result from recover: {result:?}"),
        };

        match client.recover(&pin, &user_info).await {
            Err(RecoverError::InvalidPin { guesses_remaining }) => {
                assert_eq!(guesses_remaining, 0);
            }
            result => panic!("Unexpected result from recover: {result:?}"),
        };

        let pin = Pin::from(b"abcd".to_vec());
        let secret = UserSecret::from(b"apollo".to_vec());
        let user_info = UserInfo::from(b"artemis".to_vec());

        client
            .register(&pin, &secret, &user_info, Policy { num_guesses: 2 })
            .await
            .expect("register failed");

        let recovered_secret = client
            .recover(&pin, &user_info)
            .await
            .expect("recover failed");
        assert_eq!(secret.expose_secret(), recovered_secret.expose_secret());

        client.delete().await.expect("delete unexpectedly failed");

        match client.recover(&pin, &user_info).await {
            Err(RecoverError::NotRegistered) => {}
            result => panic!("Unexpected result from recover: {result:?}"),
        };
    }
}
