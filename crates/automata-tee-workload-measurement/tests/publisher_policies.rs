//! Cross-check against actual V2 getter responses from the Hoodi-fork rehearsal.
use alloy::{
    primitives::{B256, Bytes},
    signers::local::PrivateKeySigner,
    sol_types::SolCall,
};
use automata_tee_workload_measurement::{
    publisher_policy::*,
    stubs::{BaseImageRegistry, WorkloadRegistry},
};
use serde_json::Value;
fn id(v: &Value) -> B256 {
    v.as_str().unwrap().parse().unwrap()
}
fn bytes(v: &Value) -> Bytes {
    v.as_str().unwrap().parse().unwrap()
}
#[tokio::test]
async fn signatures_match_actual_contract_records() {
    let f: Value = serde_json::from_str(include_str!("fixtures/publisher-policies.json")).unwrap();
    let w = WorkloadRegistry::getSignedWorkloadCall::abi_decode_returns_validate(&bytes(
        &f["workload"]["rawGetterResult"],
    ))
    .unwrap();
    let wid = id(&f["workload"]["id"]);
    assert_eq!(workload_digest(wid, &w.spec), id(&f["workload"]["digest"]));
    let signer: PrivateKeySigner = format!("{:064x}", 0xA11CEu64).parse().unwrap();
    assert_eq!(
        sign_workload(&signer, wid, &w.spec).await.unwrap(),
        w.workloadSignature
    );
    let signer: PrivateKeySigner = format!("{:064x}", 0xB0Bu64).parse().unwrap();
    let image_id = "0x9f54fde30212fc2318f9d1a22d2e8ac59e3b97f36c0d5d648b233a63ef51864b"
        .parse()
        .unwrap();
    let mut profiles = Vec::new();
    let mut rows = Vec::new();
    let mut expected = Vec::new();
    for v in f["variants"].as_array().unwrap() {
        let b = BaseImageRegistry::getSignedVariantCall::abi_decode_returns_validate(&bytes(
            &v["rawGetterResult"],
        ))
        .unwrap();
        assert_eq!(
            variant_digest(image_id, &b.platformProfile, &b.measurementVariant),
            id(&v["digest"])
        );
        if profiles.last().is_some_and(
            |p: &automata_tee_workload_measurement::stubs::PlatformProfile| {
                p.name == b.platformProfile.name
            },
        ) {
            rows.last_mut()
                .map(|r: &mut Vec<_>| r.push(b.measurementVariant));
            expected
                .last_mut()
                .map(|r: &mut Vec<_>| r.push(b.variantSignature));
        } else {
            profiles.push(b.platformProfile);
            rows.push(vec![b.measurementVariant]);
            expected.push(vec![b.variantSignature]);
        }
    }
    assert_eq!(
        sign_variants(&signer, image_id, &profiles, &rows)
            .await
            .unwrap(),
        expected
    );
    assert!(
        sign_variants(&signer, image_id, &profiles, &[])
            .await
            .is_err()
    );
}
