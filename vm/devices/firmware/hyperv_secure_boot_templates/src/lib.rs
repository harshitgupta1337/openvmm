// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

#![expect(missing_docs)]
#![forbid(unsafe_code)]

//! A basic "resource" crate which contains hard-coded Hyper-V Secure Boot
//! Template JSON files which can be embedded directly into a final binary.
//!
//! This crate should not include any `cfg(target_arch)` or `cfg(guest_arch)`
//! gates! Unused templates should be stripped from the final binary by the
//! linker.

use firmware_uefi_custom_vars::CustomVars;
use firmware_uefi_custom_vars::Signature;
use firmware_uefi_custom_vars::Signatures;

fn signatures_equal(left: &Signature, right: &Signature) -> bool {
    match (left, right) {
        (Signature::X509(left), Signature::X509(right)) => left
            .iter()
            .map(|cert| cert.0.as_slice())
            .eq(right.iter().map(|cert| cert.0.as_slice())),
        (Signature::Sha256(left), Signature::Sha256(right)) => left
            .iter()
            .map(|digest| digest.0)
            .eq(right.iter().map(|digest| digest.0)),
        _ => false,
    }
}

fn union_signatures(base: &mut Vec<Signature>, additional: Vec<Signature>) {
    for signature in additional {
        match signature {
            Signature::X509(certs) => {
                for cert in certs {
                    if base.iter().any(|signature| match signature {
                        Signature::X509(existing) => existing
                            .iter()
                            .any(|item| item.0.as_slice() == cert.0.as_slice()),
                        Signature::Sha256(_) => false,
                    }) {
                        continue;
                    }

                    match base
                        .iter_mut()
                        .find(|signature| matches!(signature, Signature::X509(_)))
                    {
                        Some(Signature::X509(existing)) => existing.push(cert),
                        _ => base.push(Signature::X509(vec![cert])),
                    }
                }
            }
            Signature::Sha256(digests) => {
                for digest in digests {
                    if base.iter().any(|signature| match signature {
                        Signature::X509(_) => false,
                        Signature::Sha256(existing) => {
                            existing.iter().any(|item| item.0 == digest.0)
                        }
                    }) {
                        continue;
                    }

                    match base
                        .iter_mut()
                        .find(|signature| matches!(signature, Signature::Sha256(_)))
                    {
                        Some(Signature::Sha256(existing)) => existing.push(digest),
                        _ => base.push(Signature::Sha256(vec![digest])),
                    }
                }
            }
        }
    }
}

fn merge_templates(mut base: CustomVars, additional: CustomVars) -> CustomVars {
    let Signatures {
        pk: additional_pk,
        kek: additional_kek,
        db: additional_db,
        dbx: additional_dbx,
        moklist: additional_moklist,
        moklistx: additional_moklistx,
    } = additional
        .signatures
        .expect("secure boot template must contain signatures");
    let base_signatures = base
        .signatures
        .as_mut()
        .expect("secure boot template must contain signatures");

    assert!(
        signatures_equal(&base_signatures.pk, &additional_pk),
        "cannot merge secure boot templates with different platform keys"
    );
    union_signatures(&mut base_signatures.kek, additional_kek);
    union_signatures(&mut base_signatures.db, additional_db);
    union_signatures(&mut base_signatures.dbx, additional_dbx);
    union_signatures(&mut base_signatures.moklist, additional_moklist);
    union_signatures(&mut base_signatures.moklistx, additional_moklistx);

    for (name, var) in additional.custom_vars {
        match base
            .custom_vars
            .iter()
            .find(|(existing_name, existing_var)| {
                existing_name == &name && existing_var.guid == var.guid
            }) {
            Some((_, existing_var)) => assert!(
                existing_var.attr == var.attr && existing_var.value == var.value,
                "cannot merge conflicting custom UEFI variable {name}"
            ),
            None => base.custom_vars.push((name, var)),
        }
    }

    base
}

macro_rules! include_templates {
    (
        $(($fn_name:ident, $path:literal),)*
    ) => {
        $(
            pub fn $fn_name() -> firmware_uefi_custom_vars::CustomVars {
                // DEVNOTE: in the future, it may be interesting to explore
                // parsing the JSON at compile time, and then "baking" the
                // parsed templates into the binary as a `const` value, instead
                // of baking in the JSON and doing this extra "useless" parsing
                // + validation at runtime.
                //
                // While it's unlikely this would save all that much code space
                // in the final bin (given that much of the parsing + validation
                // code is shared between both templates and user custom uefi
                // JSON files), it may result in a nice .rodata size decrease.
                hyperv_uefi_custom_vars_json::load_template_from_json(include_bytes!(concat!(env!("OUT_DIR"), "/", $path))).unwrap()
            }
        )*

        #[cfg(test)]
        mod test {
            $(
                #[test]
                fn $fn_name() {
                    super::$fn_name();
                }
            )*
        }

    };
}

pub mod aarch64 {
    include_templates! {
        (microsoft_windows, "aarch64/MicrosoftWindows_Template.json"),
        (microsoft_uefi_ca, "aarch64/MicrosoftUEFI_Template.json"),
    }

    pub fn microsoft_composite() -> firmware_uefi_custom_vars::CustomVars {
        super::merge_templates(microsoft_windows(), microsoft_uefi_ca())
    }
}

pub mod x64 {
    include_templates! {
        (microsoft_windows, "x64/MicrosoftWindows_Template.json"),
        (microsoft_windows_confidential, "x64/MicrosoftWindows_Confidential_Template.json"),
        (microsoft_uefi_ca, "x64/MicrosoftUEFI_Template.json"),
        (microsoft_uefi_ca_confidential, "x64/MicrosoftUEFI_Confidential_Template.json"),
    }

    pub fn microsoft_composite() -> firmware_uefi_custom_vars::CustomVars {
        super::merge_templates(microsoft_windows(), microsoft_uefi_ca())
    }

    pub fn microsoft_composite_confidential() -> firmware_uefi_custom_vars::CustomVars {
        super::merge_templates(
            microsoft_windows_confidential(),
            microsoft_uefi_ca_confidential(),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use firmware_uefi_custom_vars::X509Cert;
    use std::collections::BTreeSet;

    fn signature_values(signatures: &[Signature]) -> BTreeSet<(u8, Vec<u8>)> {
        signatures
            .iter()
            .flat_map(|signature| match signature {
                Signature::X509(certs) => certs
                    .iter()
                    .map(|cert| (0, cert.0.clone()))
                    .collect::<Vec<_>>(),
                Signature::Sha256(digests) => digests
                    .iter()
                    .map(|digest| (1, digest.0.to_vec()))
                    .collect(),
            })
            .collect()
    }

    fn assert_is_union(left: &[Signature], right: &[Signature], composite: &[Signature]) {
        let expected = signature_values(left)
            .union(&signature_values(right))
            .cloned()
            .collect::<BTreeSet<_>>();
        let actual = signature_values(composite);

        assert_eq!(actual, expected);
        assert_eq!(actual.len(), signature_value_count(composite));
    }

    fn signature_value_count(signatures: &[Signature]) -> usize {
        signatures
            .iter()
            .map(|signature| match signature {
                Signature::X509(certs) => certs.len(),
                Signature::Sha256(digests) => digests.len(),
            })
            .sum()
    }

    fn verify_composite(windows: CustomVars, uefi_ca: CustomVars, composite: CustomVars) {
        let windows = windows.signatures.unwrap();
        let uefi_ca = uefi_ca.signatures.unwrap();
        let composite = composite.signatures.unwrap();

        assert!(signatures_equal(&windows.pk, &uefi_ca.pk));
        assert!(signatures_equal(&windows.pk, &composite.pk));
        assert_is_union(&windows.kek, &uefi_ca.kek, &composite.kek);
        assert_is_union(&windows.db, &uefi_ca.db, &composite.db);
        assert_is_union(&windows.dbx, &uefi_ca.dbx, &composite.dbx);
        assert_is_union(&windows.moklist, &uefi_ca.moklist, &composite.moklist);
        assert_is_union(&windows.moklistx, &uefi_ca.moklistx, &composite.moklistx);
    }

    #[test]
    fn x64_composite_is_union() {
        verify_composite(
            x64::microsoft_windows(),
            x64::microsoft_uefi_ca(),
            x64::microsoft_composite(),
        );
    }

    #[test]
    fn x64_confidential_composite_is_union() {
        verify_composite(
            x64::microsoft_windows_confidential(),
            x64::microsoft_uefi_ca_confidential(),
            x64::microsoft_composite_confidential(),
        );
    }

    #[test]
    fn aarch64_composite_is_union() {
        verify_composite(
            aarch64::microsoft_windows(),
            aarch64::microsoft_uefi_ca(),
            aarch64::microsoft_composite(),
        );
    }

    #[test]
    #[should_panic(expected = "different platform keys")]
    fn composite_rejects_different_platform_keys() {
        fn template(pk: &[u8]) -> CustomVars {
            CustomVars {
                signatures: Some(Signatures {
                    pk: Signature::X509(vec![X509Cert(pk.to_vec())]),
                    kek: Vec::new(),
                    db: Vec::new(),
                    dbx: Vec::new(),
                    moklist: Vec::new(),
                    moklistx: Vec::new(),
                }),
                custom_vars: Vec::new(),
            }
        }

        merge_templates(template(b"first"), template(b"second"));
    }
}
