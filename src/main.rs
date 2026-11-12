use clap::{Parser, ValueEnum};
use std::io::{self, Write};
use std::process::ExitCode;

#[derive(Parser)]
#[command(
    version,
    about = "Display real, effective, and saved user IDs for this Linux process",
    long_about = "Display real, effective, and saved user IDs for this Linux process.\n\nReal IDs identify the process's user and primary group. Effective IDs are used for permission checks. Saved set-user-ID and set-group-ID values allow a process to restore a previous effective ID.\n\nOnly this process is inspected; credentials are never modified and elevated privileges are unnecessary.\n\nThe Linux getresuid(2) manual describes the returned credentials:\nhttps://man7.org/linux/man-pages/man2/getresuid.2.html"
)]
struct Args {
    #[arg(long, help = "Include real, effective, and saved group IDs")]
    groups: bool,
    #[arg(long, value_enum, help = "Select one field for each requested ID set")]
    field: Option<Field>,
    #[arg(long, help = "Emit numeric credentials as JSON with stable keys")]
    json: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, ValueEnum)]
enum Field {
    Real,
    Effective,
    Saved,
}

impl Field {
    fn name(self) -> &'static str {
        match self {
            Self::Real => "real",
            Self::Effective => "effective",
            Self::Saved => "saved",
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
struct Ids {
    real: u32,
    effective: u32,
    saved: u32,
}

impl Ids {
    fn get(&self, field: Field) -> u32 {
        match field {
            Field::Real => self.real,
            Field::Effective => self.effective,
            Field::Saved => self.saved,
        }
    }
}

#[cfg(target_os = "linux")]
unsafe extern "C" {
    fn getresuid(real: *mut u32, effective: *mut u32, saved: *mut u32) -> std::ffi::c_int;
    fn getresgid(real: *mut u32, effective: *mut u32, saved: *mut u32) -> std::ffi::c_int;
}

#[cfg(target_os = "linux")]
fn query(groups: bool) -> Result<(Ids, Option<Ids>), String> {
    fn read(
        call: unsafe extern "C" fn(*mut u32, *mut u32, *mut u32) -> std::ffi::c_int,
        name: &str,
    ) -> Result<Ids, String> {
        let mut ids = Ids {
            real: 0,
            effective: 0,
            saved: 0,
        };
        let status = unsafe { call(&mut ids.real, &mut ids.effective, &mut ids.saved) };
        if status != 0 {
            return Err(format!("{name} failed: {}", io::Error::last_os_error()));
        }
        Ok(ids)
    }

    let user = read(getresuid, "getresuid")?;
    let group = if groups {
        Some(read(getresgid, "getresgid")?)
    } else {
        None
    };
    Ok((user, group))
}

#[cfg(not(target_os = "linux"))]
fn query(_groups: bool) -> Result<(Ids, Option<Ids>), String> {
    Err("unsupported platform: getresuid requires Linux".to_owned())
}

fn render(args: &Args, user: &Ids, group: Option<&Ids>) -> String {
    let mut entries = Vec::new();
    for (set, ids) in [("uid", Some(user)), ("gid", group)] {
        if let Some(ids) = ids {
            for field in [Field::Real, Field::Effective, Field::Saved] {
                if args.field.is_some_and(|selected| selected != field) {
                    continue;
                }
                let name = field.name();
                let value = ids.get(field);
                entries.push(if args.json {
                    format!("\"{name}_{set}\":{value}")
                } else {
                    format!("{name} {set}: {value}")
                });
            }
        }
    }
    if args.json {
        format!("{{{}}}\n", entries.join(","))
    } else {
        format!("{}\n", entries.join("\n"))
    }
}

fn run(args: &Args) -> Result<(), String> {
    let (user, group) = query(args.groups)?;
    io::stdout()
        .lock()
        .write_all(render(args, &user, group.as_ref()).as_bytes())
        .map_err(|error| format!("could not write credentials: {error}"))
}

fn main() -> ExitCode {
    let args = Args::parse();
    match run(&args) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("getresuid: {error}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn user() -> Ids {
        Ids {
            real: 1000,
            effective: 0,
            saved: u32::MAX,
        }
    }

    #[test]
    fn default_output_labels_all_user_ids() {
        let args = Args::try_parse_from(["getresuid"]).unwrap();
        assert_eq!(
            render(&args, &user(), None),
            "real uid: 1000\neffective uid: 0\nsaved uid: 4294967295\n"
        );
    }

    #[test]
    fn effective_json_selects_both_id_sets() {
        let args =
            Args::try_parse_from(["getresuid", "--groups", "--json", "--field", "effective"])
                .unwrap();
        let group = Ids {
            real: 100,
            effective: 200,
            saved: 300,
        };
        assert_eq!(
            render(&args, &user(), Some(&group)),
            "{\"effective_uid\":0,\"effective_gid\":200}\n"
        );
    }

    #[test]
    fn json_preserves_all_numeric_user_fields() {
        let args = Args::try_parse_from(["getresuid", "--json"]).unwrap();
        assert_eq!(
            render(&args, &user(), None),
            "{\"real_uid\":1000,\"effective_uid\":0,\"saved_uid\":4294967295}\n"
        );
    }

    #[test]
    fn field_selection_covers_real_and_saved() {
        for (field, expected) in [
            ("real", "real uid: 1000\n"),
            ("saved", "saved uid: 4294967295\n"),
        ] {
            let args = Args::try_parse_from(["getresuid", "--field", field]).unwrap();
            assert_eq!(render(&args, &user(), None), expected);
        }
    }

    #[test]
    fn malformed_arguments_are_rejected() {
        for arguments in [
            vec!["getresuid", "--field", "unknown"],
            vec!["getresuid", "--field"],
            vec!["getresuid", "--unknown"],
            vec!["getresuid", "123"],
        ] {
            assert!(Args::try_parse_from(arguments).is_err());
        }
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_queries_both_id_sets() {
        let (_, group) = query(true).unwrap();
        assert!(group.is_some());
        assert!(query(false).unwrap().1.is_none());
    }

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn other_platforms_report_linux_requirement() {
        assert_eq!(
            query(true).unwrap_err(),
            "unsupported platform: getresuid requires Linux"
        );
    }
}
