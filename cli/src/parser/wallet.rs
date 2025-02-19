use clap::ArgMatches;

pub fn parse<'a>(args: &'a ArgMatches<'_>) -> Command<'a> {
    if args.is_present("provider-configuration") {
        return get_provider_configuration(
            &args
                .subcommand_matches("provider-configuration")
                .expect("Error parsing request"),
        );
    } else if args.is_present("create") {
        return create(
            &args
                .subcommand_matches("create")
                .expect("Error parsing request"),
        );
    } else if args.is_present("search") {
        return search(
            &args
                .subcommand_matches("search")
                .expect("Error parsing request"),
        );
    } else if args.is_present("insert-item") {
        return insert_item(
            &args
                .subcommand_matches("insert-item")
                .expect("Error parsing request"),
        );
    } else if args.is_present("send") {
        return send(
            &args
                .subcommand_matches("send")
                .expect("Error parsing request"),
        );
    } else {
        panic!("Unrecognized command")
    }
}

fn create<'a>(args: &'a ArgMatches<'_>) -> Command<'a> {
    Command::Create(CreateArgs {
        description: args.value_of("description"),
        profile_name: args.value_of("name"),
        encrypted: args.value_of("encrypted").is_some(),
        key: args.value_of("key"),
        set_default: args.is_present("default"),
        security_code: args.value_of("security-code"),
    })
}

fn search<'a>(args: &'a ArgMatches<'_>) -> Command<'a> {
    Command::Search(SearchArgs {
        query: args.value_of("query"),
    })
}

fn insert_item<'a>(args: &'a ArgMatches<'_>) -> Command<'a> {
    Command::InsertItem(InsertItemArgs {
        item_type: args.value_of("type"),
        item: args.value_of("item"),
    })
}

fn send<'a>(args: &'a ArgMatches<'_>) -> Command<'a> {
    Command::Send(SendArgs {
        email: args.value_of("email"),
        item: args.value_of("item"),
    })
}

fn get_provider_configuration<'a>(_args: &'a ArgMatches<'_>) -> Command<'a> {
    Command::GetProviderConfiguration
}

#[derive(Debug, PartialEq)]
pub enum Command<'a> {
    Create(CreateArgs<'a>),
    Search(SearchArgs<'a>),
    InsertItem(InsertItemArgs<'a>),
    Send(SendArgs<'a>),
    GrantAccess,
    RevokeAccess,
    GetProviderConfiguration,
}

#[derive(Debug, PartialEq)]
pub struct CreateArgs<'a> {
    pub description: Option<&'a str>,
    pub profile_name: Option<&'a str>,
    pub security_code: Option<&'a str>,
    pub encrypted: bool,
    pub key: Option<&'a str>,
    pub set_default: bool,
}

#[derive(Debug, PartialEq)]
pub struct SearchArgs<'a> {
    pub query: Option<&'a str>,
}

#[derive(Debug, PartialEq)]
pub struct InsertItemArgs<'a> {
    pub item_type: Option<&'a str>,
    pub item: Option<&'a str>,
}

#[derive(Debug, PartialEq)]
pub struct SendArgs<'a> {
    pub email: Option<&'a str>,
    pub item: Option<&'a str>,
}

#[derive(Debug, PartialEq)]
pub struct SetProfileArgs<'a> {
    pub out: Option<&'a str>,
    pub profile: Option<&'a str>,
}
