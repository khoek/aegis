use super::*;
use firestore::FirestoreDbOptions;
use phylax_gcp::identity::RefreshTokenConfig;
use phylax_gcp::identity::UserRecord;

#[tokio::test]
#[ignore = "requires FIRESTORE_EMULATOR_HOST; never connects to production"]
async fn namespace_subtrees_isolate_records_transactions_membership_and_credentials()
-> anyhow::Result<()> {
    let emulator = std::env::var("FIRESTORE_EMULATOR_HOST")?;
    anyhow::ensure!(emulator.starts_with("127.0.0.1:"), "use a local emulator");
    tokio::time::timeout(std::time::Duration::from_secs(60), exercise_namespaces()).await??;
    Ok(())
}

async fn exercise_namespaces() -> anyhow::Result<()> {
    let db = Db::from_firestore(
        FirestoreDb::with_options(FirestoreDbOptions::new(format!(
            "aegis-test-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)?
                .as_nanos()
        )))
        .await?,
    );
    let alice = AegisDb::new(db.clone(), "alice".parse()?);
    let bob = AegisDb::new(db.clone(), "bob".parse()?);
    let host_id: HostId = "00000000-0000-0000-0000-000000000001".parse()?;
    for (store, created_unix) in [(&alice, 10), (&bob, 20)] {
        let host = StoredAegisHostRecord {
            aliases: HostAliases::new(vec!["same-name".parse()?])?,
            ssh: None,
            egress: None,
            report: StoredAegisHostReport::default(),
            transient: false,
            pending: false,
            created_unix,
            updated: Some(StoredAegisHostRecordUpdated {
                unix: created_unix,
                by_principal: "operator".into(),
            }),
        };
        store
            .inner()
            .fluent()
            .insert()
            .into("hosts")
            .document_id(host_id.to_string())
            .parent(&store.parent)
            .object(&host)
            .execute::<()>()
            .await?;
        store
            .inner()
            .fluent()
            .insert()
            .into("aliases")
            .document_id("same-name")
            .parent(&store.parent)
            .object(&StoredAegisAliasClaim { host_id })
            .execute::<()>()
            .await?;
    }
    assert_eq!(alice.list_aegis_hosts().await?[0].created_unix, 10);
    assert_eq!(bob.list_aegis_hosts().await?[0].created_unix, 20);
    alice
        .add_host_alias(&host_id, &"alice-only".parse()?, "operator", 30)
        .await?;
    assert_eq!(
        alice
            .resolve_enrolled_host_alias(&"alice-only".parse()?)
            .await?,
        Some(host_id)
    );
    assert_eq!(
        bob.resolve_enrolled_host_alias(&"alice-only".parse()?)
            .await?,
        None
    );
    assert!(alice.delete_aegis_host(&host_id, &[]).await?);
    assert!(alice.fetch_aegis_host(&host_id).await?.is_none());
    assert!(bob.fetch_aegis_host(&host_id).await?.is_some());
    assert_eq!(
        bob.resolve_enrolled_host_alias(&"same-name".parse()?)
            .await?,
        Some(host_id)
    );

    db.inner()
        .fluent()
        .insert()
        .into("users")
        .document_id("user-1")
        .parent(crate::identity::store(&db)?.parent())
        .object(&UserRecord {
            id: "user-1".into(),
            email: "test@example.test".into(),
            disabled: false,
            session_version: 1,
        })
        .execute::<()>()
        .await?;
    alice
        .inner()
        .fluent()
        .insert()
        .into("members")
        .document_id("user-1")
        .parent(&alice.parent)
        .object(&aegis_types::NamespaceMembership {
            role: aegis_types::NamespaceRole::Member,
        })
        .execute::<()>()
        .await?;
    assert!(!alice.fetch_aegis_user_by_id("user-1").await?.unwrap().admin);
    assert!(bob.fetch_aegis_user_by_id("user-1").await?.is_none());

    let refresh = RefreshTokenConfig {
        pepper: "test-pepper".into(),
        ttl_seconds: 3600,
    };
    let alice_auth = alice.auth_store(&refresh, 300)?;
    let bob_auth = bob.auth_store(&refresh, 300)?;
    let issued = alice_auth
        .issue_refresh_token(phylax_gcp::RefreshTokenIssueRequest {
            subject: phylax_core::Subject::new(format!("host:{host_id}"))?,
            client_id: "aegis-agent",
            now_unix: 100,
        })
        .await?;
    let grant = phylax_gcp::RefreshTokenGrantRequest {
        refresh_token: issued.refresh_token(),
        client_id: "aegis-agent",
        now_unix: 101,
    };
    assert!(matches!(
        bob_auth.exchange_refresh_token(grant).await?,
        phylax_core::RefreshTokenValidation::Invalid
    ));
    assert!(matches!(
        alice_auth.exchange_refresh_token(grant).await?,
        phylax_core::RefreshTokenValidation::Valid(_)
    ));

    ensure_client_ca_config(&alice).await?;
    ensure_client_ca_config(&bob).await?;
    let alice_ca = load_client_ca_config(&alice).await?;
    let bob_ca = load_client_ca_config(&bob).await?;
    assert_ne!(alice_ca.private_key_pem, bob_ca.private_key_pem);
    Ok(())
}
