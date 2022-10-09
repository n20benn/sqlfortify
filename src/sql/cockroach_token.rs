use crate::sql::*;
use phf::phf_map;
use std::fmt::Display;
use std::hash::{Hash, Hasher};

// Derived from https://www.cockroachlabs.com/docs/stable/sql-grammar.html
// And more importantly,https://github.com/cockroachdb/cockroach/blob/release-22.1.0/docs/generated/sql/bnf/stmt_block.bnf
// Note: v21.2.10

// Full scanner described here: https://github.com/cockroachdb/cockroach/blob/master/pkg/sql/parser/scanner_test.go

#[derive(Clone, Debug)]
pub enum CockroachToken {
    UnknownToken(char),
    Identifier(String), // must: begin with underscore?; subsequent alphanumeric, underscores, or dollar signs. Double-quotes bypass these rules and preserves case sensitivity. Examples include asdf and "asdf", as well as $asdf
    SingleQuote,
    DoubleQuote,
    DollarQuote(String),
    Const(String),
    Placeholder(String), // looks like $1, must be betweeen 1 and 65536 (we don't enforce)
    Keyword(Keyword),
    Symbol(char), // Characters that form unary/binary operators
    LineComment,
    BlockCommentOpen,
    BlockCommentClose,
    Comment(String),
    Whitespace(char),
}

#[derive(PartialEq, Eq)]
enum ScanDirection {
    Forward,
    Reverse,
}

// These are all accepted keywords
#[derive(PartialEq, Eq, Hash, Clone, Copy, Debug, Display)]
pub enum Keyword {
    Analyze,
    Analyse,
    Copy,
    From,
    Stdin,
    Comment,
    On,
    Database,
    Is,
    Schema,
    Table,
    Column,
    Index,
    Constraint,
    Execute,
    Deallocate,
    Prepare,
    All,
    Discard,
    Grant,
    To,
    With,
    Admin,
    Option,
    Type,
    Tables,
    In,
    As,
    Revoke,
    For,
    Savepoint,
    Reassign,
    Owned,
    By,
    Drop,
    Release,
    Refresh,
    Materialized,
    View,
    Close,
    Declare,
    Cursor,
    Fetch,
    Move,
    Backup,
    Into,
    Latest,
    Delete,
    Explain,
    Import,
    Data,
    Insert,
    Restore,
    System,
    Users,
    Replication,
    Stream,
    Export,
    Truncate,
    Update,
    Set,
    Upsert,
    Null,
    Tenant,
    CurrentUser,
    SessionUser,
    Cascade,
    Restrict,
    Concurrently,
    No,
    Transaction,
    Session,
    Begin,
    Start,
    Commit,
    End,
    Rollback,
    Abort,
    Binary,
    Insensitive,
    Asensitive,
    Scroll,
    Hold,
    Without,
    Absolute,
    Relative,
    First,
    Last,
    Alter,
    If,
    Exists,
    RoleAll,
    UserAll,
    TenantAll,
    Options,
    Incremental,
    Cancel,
    Job,
    Jobs,
    Query,
    Queries,
    Sessions,
    Create,
    Not,
    Statistics,
    Schedule,
    Changefeed,
    Extension,
    Returning,
    Nothing,
    Schedules,
    Default,
    Values,
    Conflict,
    Do,
    Pause,
    Reason,
    Reset,
    ResetAll,
    Cluster,
    Setting,
    Resume,
    Experimental,
    Scrub,
    Characteristics,
    Local,
    Use,
    Show,
    Backups,
    Schemas,
    Files,
    Ranges,
    Columns,
    Constraints,
    Types,
    Databases,
    Enums,
    Grants,
    Indexes,
    Keys,
    Partitions,
    Automatic,
    When,
    Complete,
    Locality,
    Range,
    Row,
    Regions,
    Super,
    Survival,
    Goal,
    Roles,
    Status,
    Sequences,
    Trace,
    Kv,
    Transactions,
    Transfer,
    State,
    Zone,
    Configuration,
    Partition,
    Of,
    Configurations,
    Full,
    Scans,
    Privileges,
    Where,
    Action,
    Access,
    Add,
    After,
    Aggregate,
    Always,
    At,
    Attribute,
    Availability,
    Backward,
    Before,
    BucketCount,
    Bundle,
    Cache,
    Cancelquery,
    Comments,
    Committed,
    Compact,
    Completions,
    Configure,
    Connection,
    Controlchangefeed,
    Controljob,
    Conversion,
    Convert,
    Covering,
    Createdb,
    Createlogin,
    Createrole,
    Csv,
    Cube,
    Current,
    Cycle,
    Day,
    DebugPauseOn,
    Defaults,
    Deferred,
    Delimiter,
    Destination,
    Detached,
    Domain,
    Double,
    Encoding,
    Encrypted,
    EncryptionPassphrase,
    Enum,
    Escape,
    Exclude,
    Excluding,
    Execution,
    ExperimentalAudit,
    ExperimentalFingerprints,
    ExperimentalRelocate,
    ExperimentalReplica,
    Expiration,
    Failure,
    Filter,
    Following,
    Force,
    ForceIndex,
    ForceZigzag,
    Forward,
    Freeze,
    Function,
    Functions,
    Generated,
    Geometrym,
    Geometryz,
    Geometryzm,
    Geometrycollection,
    Geometrycollectionm,
    Geometrycollectionz,
    Geometrycollectionzm,
    Global,
    Groups,
    Hash,
    Header,
    High,
    Histogram,
    Hour,
    Identity,
    Immediate,
    Include,
    Including,
    Increment,
    IncrementalLocation,
    Inherits,
    Inject,
    IntoDb,
    Inverted,
    Isolation,
    Json,
    Key,
    Kms,
    Language,
    LcCollate,
    LcCtype,
    Lease,
    Less,
    Level,
    Linestring,
    Linestringm,
    Linestringz,
    Linestringzm,
    List,
    Locked,
    Login,
    Lookup,
    Low,
    Match,
    Maxvalue,
    Merge,
    Method,
    Minute,
    Minvalue,
    Modifyclustersetting,
    Multilinestring,
    Multilinestringm,
    Multilinestringz,
    Multilinestringzm,
    Multipoint,
    Multipointm,
    Multipointz,
    Multipointzm,
    Multipolygon,
    Multipolygonm,
    Multipolygonz,
    Multipolygonzm,
    Month,
    Names,
    Nan,
    Never,
    NewDbName,
    NewKms,
    Next,
    Normal,
    NoIndexJoin,
    NoZigzagJoin,
    NoFullScan,
    Nocreatedb,
    Nocreatelogin,
    Nocancelquery,
    Nocreaterole,
    Nocontrolchangefeed,
    Nocontroljob,
    Nologin,
    Nomodifyclustersetting,
    Nonvoters,
    Nosqllogin,
    Noviewactivity,
    Noviewactivityredacted,
    Noviewclustersetting,
    Nowait,
    Nulls,
    IgnoreForeignKeys,
    Off,
    Oids,
    OldKms,
    Operator,
    Opt,
    Ordinality,
    Others,
    Over,
    Owner,
    Parent,
    Partial,
    Password,
    Paused,
    Physical,
    Placement,
    Plan,
    Plans,
    Pointm,
    Pointz,
    Pointzm,
    Polygonm,
    Polygonz,
    Polygonzm,
    Preceding,
    Preserve,
    Prior,
    Priority,
    Public,
    Publication,
    Quote,
    Read,
    Recurring,
    Recursive,
    Ref,
    Region,
    Regional,
    Reindex,
    Relocate,
    Rename,
    Repeatable,
    Replace,
    Restricted,
    Retry,
    RevisionHistory,
    Role,
    Rollup,
    Routines,
    Rows,
    Rule,
    Running,
    Settings,
    Scatter,
    Search,
    Second,
    Serializable,
    Sequence,
    Server,
    Sets,
    Share,
    Simple,
    Skip,
    SkipLocalitiesCheck,
    SkipMissingForeignKeys,
    SkipMissingSequences,
    SkipMissingSequenceOwners,
    SkipMissingViews,
    Snapshot,
    Split,
    Sql,
    Sqllogin,
    Statements,
    Storage,
    Store,
    Stored,
    Storing,
    Strict,
    Subscription,
    Survive,
    Syntax,
    Tablespace,
    Temp,
    Template,
    Temporary,
    TestingRelocate,
    Text,
    Ties,
    Trigger,
    Trusted,
    Throttling,
    Unbounded,
    Uncommitted,
    Unknown,
    Unlogged,
    Unset,
    Unsplit,
    Until,
    Valid,
    Validate,
    Value,
    Varying,
    Viewactivity,
    Viewactivityredacted,
    Viewclustersetting,
    Visible,
    Voters,
    Within,
    Write,
    Year,
    AnnotateType,
    Between,
    Bigint,
    Bit,
    Boolean,
    Box2d,
    Char,
    Character,
    Coalesce,
    Dec,
    Decimal,
    Extract,
    ExtractDuration,
    Float,
    Geography,
    Geometry,
    Greatest,
    Grouping,
    Iferror,
    Ifnull,
    Int,
    Integer,
    Interval,
    Iserror,
    Least,
    Nullif,
    Numeric,
    Out,
    Overlay,
    Point,
    Polygon,
    Position,
    Precision,
    Real,
    Smallint,
    String,
    Substring,
    Time,
    Timetz,
    Timestamp,
    Timestamptz,
    Treat,
    Trim,
    Varbit,
    Varchar,
    Virtual,
    Work,
    Select,
    User,
    True,
    False,
    Array,
    Typeannotate,
    Collate,
    JsonSomeExists,
    JsonAllExists,
    Contains,
    ContainedBy,
    Fetchval,
    Fetchtext,
    FetchvalPath,
    FetchtextPath,
    RemovePath,
    And,
    Or,
    Like,
    Ilike,
    Similar,
    Isnull,
    Notnull,
    Distinct,
    Symmetric,
    Authorization,
    Order,
    Limit,
    Only,
    Asymmetric,
    Any,
    Some,
    Unique,
    Using,
    Family,
    Union,
    Intersect,
    Except,
    Offset,
    Lateral,
    Asc,
    Both,
    Case,
    Cast,
    Check,
    CurrentCatalog,
    CurrentDate,
    CurrentRole,
    CurrentSchema,
    CurrentTime,
    CurrentTimestamp,
    Deferrable,
    Desc,
    Else,
    Foreign,
    Group,
    Having,
    Initially,
    Leading,
    Localtime,
    Localtimestamp,
    Placing,
    Primary,
    References,
    Then,
    Trailing,
    Variadic,
    Window,
    Collation,
    Cross,
    Join,
    Natural,
    Inner,
    Left,
    None,
    Outer,
    Overlaps,
    Right,
    Date,
    GeneratedAlways,
    GeneratedByDefault,
}

// TODO: pull this out into type; this looks messy.
impl Keyword {
    pub fn is_reserved(&self) -> bool {
        match self {
            Keyword::All
            | Keyword::Analyze
            | Keyword::Analyse
            | Keyword::And
            | Keyword::Any
            | Keyword::Array
            | Keyword::As
            | Keyword::Asc
            | Keyword::Asymmetric
            | Keyword::Both
            | Keyword::Case
            | Keyword::Cast
            | Keyword::Check
            | Keyword::Collate
            | Keyword::Column
            | Keyword::Concurrently
            | Keyword::Constraint
            | Keyword::Create
            | Keyword::CurrentCatalog
            | Keyword::CurrentDate
            | Keyword::CurrentRole
            | Keyword::CurrentSchema
            | Keyword::CurrentTime
            | Keyword::CurrentTimestamp
            | Keyword::CurrentUser
            | Keyword::Default
            | Keyword::Deferrable
            | Keyword::Desc
            | Keyword::Distinct
            | Keyword::Do
            | Keyword::Else
            | Keyword::End
            | Keyword::Except
            | Keyword::False
            | Keyword::Fetch
            | Keyword::For
            | Keyword::Foreign
            | Keyword::From
            | Keyword::Grant
            | Keyword::Group
            | Keyword::Having
            | Keyword::In
            | Keyword::Initially
            | Keyword::Intersect
            | Keyword::Into
            | Keyword::Lateral
            | Keyword::Leading
            | Keyword::Limit
            | Keyword::Localtime
            | Keyword::Localtimestamp
            | Keyword::Not
            | Keyword::Null
            | Keyword::Offset
            | Keyword::On
            | Keyword::Only
            | Keyword::Or
            | Keyword::Order
            | Keyword::Placing
            | Keyword::Primary
            | Keyword::References
            | Keyword::Returning
            | Keyword::Select
            | Keyword::SessionUser
            | Keyword::Some
            | Keyword::Symmetric
            | Keyword::Table
            | Keyword::Then
            | Keyword::To
            | Keyword::Trailing
            | Keyword::True
            | Keyword::Union
            | Keyword::Unique
            | Keyword::User
            | Keyword::Using
            | Keyword::Variadic
            | Keyword::When
            | Keyword::Where
            | Keyword::Window
            | Keyword::With => true,
            _ => false,
        }
    }
}

static KEYWORDS: phf::Map<&'static str, CockroachToken> = phf_map! {
    "ALL" => CockroachToken::Keyword(Keyword::All),
    "ANALYZE" => CockroachToken::Keyword(Keyword::Analyze),
    "ANALYSE" => CockroachToken::Keyword(Keyword::Analyse),
    "AND" => CockroachToken::Keyword(Keyword::And),
    "COPY" => CockroachToken::Keyword(Keyword::Copy),
    "FROM" => CockroachToken::Keyword(Keyword::From),
    "STDIN" => CockroachToken::Keyword(Keyword::Stdin),
    "COMMENT" => CockroachToken::Keyword(Keyword::Comment),
    "ON" => CockroachToken::Keyword(Keyword::On),
    "DATABASE" => CockroachToken::Keyword(Keyword::Database),
    "IS" => CockroachToken::Keyword(Keyword::Is),
    "SCHEMA" => CockroachToken::Keyword(Keyword::Schema),
    "TABLE" => CockroachToken::Keyword(Keyword::Table),
    "COLUMN" => CockroachToken::Keyword(Keyword::Column),
    "INDEX" => CockroachToken::Keyword(Keyword::Index),
    "CONSTRAINT" => CockroachToken::Keyword(Keyword::Constraint),
    "EXECUTE" => CockroachToken::Keyword(Keyword::Execute),
    "DEALLOCATE" => CockroachToken::Keyword(Keyword::Deallocate),
    "PREPARE" => CockroachToken::Keyword(Keyword::Prepare),
    "DISCARD" => CockroachToken::Keyword(Keyword::Discard),
    "GRANT" => CockroachToken::Keyword(Keyword::Grant),
    "TO" => CockroachToken::Keyword(Keyword::To),
    "WITH" => CockroachToken::Keyword(Keyword::With),
    "ADMIN" => CockroachToken::Keyword(Keyword::Admin),
    "OPTION" => CockroachToken::Keyword(Keyword::Option),
    "TYPE" => CockroachToken::Keyword(Keyword::Type),
    "TABLES" => CockroachToken::Keyword(Keyword::Tables),
    "IN" => CockroachToken::Keyword(Keyword::In),
    "AS" => CockroachToken::Keyword(Keyword::As),
    "REVOKE" => CockroachToken::Keyword(Keyword::Revoke),
    "FOR" => CockroachToken::Keyword(Keyword::For),
    "SAVEPOINT" => CockroachToken::Keyword(Keyword::Savepoint),
    "REASSIGN" => CockroachToken::Keyword(Keyword::Reassign),
    "OWNED" => CockroachToken::Keyword(Keyword::Owned),
    "BY" => CockroachToken::Keyword(Keyword::By),
    "DROP" => CockroachToken::Keyword(Keyword::Drop),
    "RELEASE" => CockroachToken::Keyword(Keyword::Release),
    "REFRESH" => CockroachToken::Keyword(Keyword::Refresh),
    "MATERIALIZED" => CockroachToken::Keyword(Keyword::Materialized),
    "VIEW" => CockroachToken::Keyword(Keyword::View),
    "CLOSE" => CockroachToken::Keyword(Keyword::Close),
    "DECLARE" => CockroachToken::Keyword(Keyword::Declare),
    "CURSOR" => CockroachToken::Keyword(Keyword::Cursor),
    "FETCH" => CockroachToken::Keyword(Keyword::Fetch),
    "MOVE" => CockroachToken::Keyword(Keyword::Move),
    "BACKUP" => CockroachToken::Keyword(Keyword::Backup),
    "INTO" => CockroachToken::Keyword(Keyword::Into),
    "LATEST" => CockroachToken::Keyword(Keyword::Latest),
    "DELETE" => CockroachToken::Keyword(Keyword::Delete),
    "EXPLAIN" => CockroachToken::Keyword(Keyword::Explain),
    "IMPORT" => CockroachToken::Keyword(Keyword::Import),
    "DATA" => CockroachToken::Keyword(Keyword::Data),
    "INSERT" => CockroachToken::Keyword(Keyword::Insert),
    "RESTORE" => CockroachToken::Keyword(Keyword::Restore),
    "SYSTEM" => CockroachToken::Keyword(Keyword::System),
    "USERS" => CockroachToken::Keyword(Keyword::Users),
    "REPLICATION" => CockroachToken::Keyword(Keyword::Replication),
    "STREAM" => CockroachToken::Keyword(Keyword::Stream),
    "EXPORT" => CockroachToken::Keyword(Keyword::Export),
    "TRUNCATE" => CockroachToken::Keyword(Keyword::Truncate),
    "UPDATE" => CockroachToken::Keyword(Keyword::Update),
    "SET" => CockroachToken::Keyword(Keyword::Set),
    "UPSERT" => CockroachToken::Keyword(Keyword::Upsert),
    "NULL" => CockroachToken::Keyword(Keyword::Null),
    "TENANT" => CockroachToken::Keyword(Keyword::Tenant),
    "CURRENT_USER" => CockroachToken::Keyword(Keyword::CurrentUser),
    "SESSION_USER" => CockroachToken::Keyword(Keyword::SessionUser),
    "CASCADE" => CockroachToken::Keyword(Keyword::Cascade),
    "RESTRICT" => CockroachToken::Keyword(Keyword::Restrict),
    "CONCURRENTLY" => CockroachToken::Keyword(Keyword::Concurrently),
    "NO" => CockroachToken::Keyword(Keyword::No),
    "TRANSACTION" => CockroachToken::Keyword(Keyword::Transaction),
    "SESSION" => CockroachToken::Keyword(Keyword::Session),
    "BEGIN" => CockroachToken::Keyword(Keyword::Begin),
    "START" => CockroachToken::Keyword(Keyword::Start),
    "COMMIT" => CockroachToken::Keyword(Keyword::Commit),
    "END" => CockroachToken::Keyword(Keyword::End),
    "ROLLBACK" => CockroachToken::Keyword(Keyword::Rollback),
    "ABORT" => CockroachToken::Keyword(Keyword::Abort),
    "BINARY" => CockroachToken::Keyword(Keyword::Binary),
    "INSENSITIVE" => CockroachToken::Keyword(Keyword::Insensitive),
    "ASENSITIVE" => CockroachToken::Keyword(Keyword::Asensitive),
    "SCROLL" => CockroachToken::Keyword(Keyword::Scroll),
    "HOLD" => CockroachToken::Keyword(Keyword::Hold),
    "WITHOUT" => CockroachToken::Keyword(Keyword::Without),
    "ABSOLUTE" => CockroachToken::Keyword(Keyword::Absolute),
    "RELATIVE" => CockroachToken::Keyword(Keyword::Relative),
    "FIRST" => CockroachToken::Keyword(Keyword::First),
    "LAST" => CockroachToken::Keyword(Keyword::Last),
    "ALTER" => CockroachToken::Keyword(Keyword::Alter),
    "IF" => CockroachToken::Keyword(Keyword::If),
    "EXISTS" => CockroachToken::Keyword(Keyword::Exists),
    "ROLE_ALL" => CockroachToken::Keyword(Keyword::RoleAll),
    "USER_ALL" => CockroachToken::Keyword(Keyword::UserAll),
    "TENANT_ALL" => CockroachToken::Keyword(Keyword::TenantAll),
    "OPTIONS" => CockroachToken::Keyword(Keyword::Options),
    "INCREMENTAL" => CockroachToken::Keyword(Keyword::Incremental),
    "CANCEL" => CockroachToken::Keyword(Keyword::Cancel),
    "JOB" => CockroachToken::Keyword(Keyword::Job),
    "JOBS" => CockroachToken::Keyword(Keyword::Jobs),
    "QUERY" => CockroachToken::Keyword(Keyword::Query),
    "QUERIES" => CockroachToken::Keyword(Keyword::Queries),
    "SESSIONS" => CockroachToken::Keyword(Keyword::Sessions),
    "CREATE" => CockroachToken::Keyword(Keyword::Create),
    "NOT" => CockroachToken::Keyword(Keyword::Not),
    "STATISTICS" => CockroachToken::Keyword(Keyword::Statistics),
    "SCHEDULE" => CockroachToken::Keyword(Keyword::Schedule),
    "CHANGEFEED" => CockroachToken::Keyword(Keyword::Changefeed),
    "EXTENSION" => CockroachToken::Keyword(Keyword::Extension),
    "RETURNING" => CockroachToken::Keyword(Keyword::Returning),
    "NOTHING" => CockroachToken::Keyword(Keyword::Nothing),
    "SCHEDULES" => CockroachToken::Keyword(Keyword::Schedules),
    "DEFAULT" => CockroachToken::Keyword(Keyword::Default),
    "VALUES" => CockroachToken::Keyword(Keyword::Values),
    "CONFLICT" => CockroachToken::Keyword(Keyword::Conflict),
    "DO" => CockroachToken::Keyword(Keyword::Do),
    "PAUSE" => CockroachToken::Keyword(Keyword::Pause),
    "REASON" => CockroachToken::Keyword(Keyword::Reason),
    "RESET" => CockroachToken::Keyword(Keyword::Reset),
    "RESET_ALL" => CockroachToken::Keyword(Keyword::ResetAll),
    "CLUSTER" => CockroachToken::Keyword(Keyword::Cluster),
    "SETTING" => CockroachToken::Keyword(Keyword::Setting),
    "RESUME" => CockroachToken::Keyword(Keyword::Resume),
    "EXPERIMENTAL" => CockroachToken::Keyword(Keyword::Experimental),
    "SCRUB" => CockroachToken::Keyword(Keyword::Scrub),
    "CHARACTERISTICS" => CockroachToken::Keyword(Keyword::Characteristics),
    "LOCAL" => CockroachToken::Keyword(Keyword::Local),
    "USE" => CockroachToken::Keyword(Keyword::Use),
    "SHOW" => CockroachToken::Keyword(Keyword::Show),
    "BACKUPS" => CockroachToken::Keyword(Keyword::Backups),
    "SCHEMAS" => CockroachToken::Keyword(Keyword::Schemas),
    "FILES" => CockroachToken::Keyword(Keyword::Files),
    "RANGES" => CockroachToken::Keyword(Keyword::Ranges),
    "COLUMNS" => CockroachToken::Keyword(Keyword::Columns),
    "CONSTRAINTS" => CockroachToken::Keyword(Keyword::Constraints),
    "TYPES" => CockroachToken::Keyword(Keyword::Types),
    "DATABASES" => CockroachToken::Keyword(Keyword::Databases),
    "ENUMS" => CockroachToken::Keyword(Keyword::Enums),
    "GRANTS" => CockroachToken::Keyword(Keyword::Grants),
    "INDEXES" => CockroachToken::Keyword(Keyword::Indexes),
    "KEYS" => CockroachToken::Keyword(Keyword::Keys),
    "PARTITIONS" => CockroachToken::Keyword(Keyword::Partitions),
    "AUTOMATIC" => CockroachToken::Keyword(Keyword::Automatic),
    "WHEN" => CockroachToken::Keyword(Keyword::When),
    "COMPLETE" => CockroachToken::Keyword(Keyword::Complete),
    "LOCALITY" => CockroachToken::Keyword(Keyword::Locality),
    "RANGE" => CockroachToken::Keyword(Keyword::Range),
    "ROW" => CockroachToken::Keyword(Keyword::Row),
    "REGIONS" => CockroachToken::Keyword(Keyword::Regions),
    "SUPER" => CockroachToken::Keyword(Keyword::Super),
    "SURVIVAL" => CockroachToken::Keyword(Keyword::Survival),
    "GOAL" => CockroachToken::Keyword(Keyword::Goal),
    "ROLES" => CockroachToken::Keyword(Keyword::Roles),
    "STATUS" => CockroachToken::Keyword(Keyword::Status),
    "SEQUENCES" => CockroachToken::Keyword(Keyword::Sequences),
    "TRACE" => CockroachToken::Keyword(Keyword::Trace),
    "KV" => CockroachToken::Keyword(Keyword::Kv),
    "TRANSACTIONS" => CockroachToken::Keyword(Keyword::Transactions),
    "TRANSFER" => CockroachToken::Keyword(Keyword::Transfer),
    "STATE" => CockroachToken::Keyword(Keyword::State),
    "ZONE" => CockroachToken::Keyword(Keyword::Zone),
    "CONFIGURATION" => CockroachToken::Keyword(Keyword::Configuration),
    "PARTITION" => CockroachToken::Keyword(Keyword::Partition),
    "OF" => CockroachToken::Keyword(Keyword::Of),
    "CONFIGURATIONS" => CockroachToken::Keyword(Keyword::Configurations),
    "FULL" => CockroachToken::Keyword(Keyword::Full),
    "SCANS" => CockroachToken::Keyword(Keyword::Scans),
    "PRIVILEGES" => CockroachToken::Keyword(Keyword::Privileges),
    "WHERE" => CockroachToken::Keyword(Keyword::Where),
    "ACTION" => CockroachToken::Keyword(Keyword::Action),
    "ACCESS" => CockroachToken::Keyword(Keyword::Access),
    "ADD" => CockroachToken::Keyword(Keyword::Add),
    "AFTER" => CockroachToken::Keyword(Keyword::After),
    "AGGREGATE" => CockroachToken::Keyword(Keyword::Aggregate),
    "ALWAYS" => CockroachToken::Keyword(Keyword::Always),
    "AT" => CockroachToken::Keyword(Keyword::At),
    "ATTRIBUTE" => CockroachToken::Keyword(Keyword::Attribute),
    "AVAILABILITY" => CockroachToken::Keyword(Keyword::Availability),
    "BACKWARD" => CockroachToken::Keyword(Keyword::Backward),
    "BEFORE" => CockroachToken::Keyword(Keyword::Before),
    "BUCKET_COUNT" => CockroachToken::Keyword(Keyword::BucketCount),
    "BUNDLE" => CockroachToken::Keyword(Keyword::Bundle),
    "CACHE" => CockroachToken::Keyword(Keyword::Cache),
    "CANCELQUERY" => CockroachToken::Keyword(Keyword::Cancelquery),
    "COMMENTS" => CockroachToken::Keyword(Keyword::Comments),
    "COMMITTED" => CockroachToken::Keyword(Keyword::Committed),
    "COMPACT" => CockroachToken::Keyword(Keyword::Compact),
    "COMPLETIONS" => CockroachToken::Keyword(Keyword::Completions),
    "CONFIGURE" => CockroachToken::Keyword(Keyword::Configure),
    "CONNECTION" => CockroachToken::Keyword(Keyword::Connection),
    "CONTROLCHANGEFEED" => CockroachToken::Keyword(Keyword::Controlchangefeed),
    "CONTROLJOB" => CockroachToken::Keyword(Keyword::Controljob),
    "CONVERSION" => CockroachToken::Keyword(Keyword::Conversion),
    "CONVERT" => CockroachToken::Keyword(Keyword::Convert),
    "COVERING" => CockroachToken::Keyword(Keyword::Covering),
    "CREATEDB" => CockroachToken::Keyword(Keyword::Createdb),
    "CREATELOGIN" => CockroachToken::Keyword(Keyword::Createlogin),
    "CREATEROLE" => CockroachToken::Keyword(Keyword::Createrole),
    "CSV" => CockroachToken::Keyword(Keyword::Csv),
    "CUBE" => CockroachToken::Keyword(Keyword::Cube),
    "CURRENT" => CockroachToken::Keyword(Keyword::Current),
    "CYCLE" => CockroachToken::Keyword(Keyword::Cycle),
    "DAY" => CockroachToken::Keyword(Keyword::Day),
    "DEBUG_PAUSE_ON" => CockroachToken::Keyword(Keyword::DebugPauseOn),
    "DEFAULTS" => CockroachToken::Keyword(Keyword::Defaults),
    "DEFERRED" => CockroachToken::Keyword(Keyword::Deferred),
    "DELIMITER" => CockroachToken::Keyword(Keyword::Delimiter),
    "DESTINATION" => CockroachToken::Keyword(Keyword::Destination),
    "DETACHED" => CockroachToken::Keyword(Keyword::Detached),
    "DOMAIN" => CockroachToken::Keyword(Keyword::Domain),
    "DOUBLE" => CockroachToken::Keyword(Keyword::Double),
    "ENCODING" => CockroachToken::Keyword(Keyword::Encoding),
    "ENCRYPTED" => CockroachToken::Keyword(Keyword::Encrypted),
    "ENCRYPTION_PASSPHRASE" => CockroachToken::Keyword(Keyword::EncryptionPassphrase),
    "ENUM" => CockroachToken::Keyword(Keyword::Enum),
    "ESCAPE" => CockroachToken::Keyword(Keyword::Escape),
    "EXCLUDE" => CockroachToken::Keyword(Keyword::Exclude),
    "EXCLUDING" => CockroachToken::Keyword(Keyword::Excluding),
    "EXECUTION" => CockroachToken::Keyword(Keyword::Execution),
    "EXPERIMENTAL_AUDIT" => CockroachToken::Keyword(Keyword::ExperimentalAudit),
    "EXPERIMENTAL_FINGERPRINTS" => CockroachToken::Keyword(Keyword::ExperimentalFingerprints),
    "EXPERIMENTAL_RELOCATE" => CockroachToken::Keyword(Keyword::ExperimentalRelocate),
    "EXPERIMENTAL_REPLICA" => CockroachToken::Keyword(Keyword::ExperimentalReplica),
    "EXPIRATION" => CockroachToken::Keyword(Keyword::Expiration),
    "FAILURE" => CockroachToken::Keyword(Keyword::Failure),
    "FILTER" => CockroachToken::Keyword(Keyword::Filter),
    "FOLLOWING" => CockroachToken::Keyword(Keyword::Following),
    "FORCE" => CockroachToken::Keyword(Keyword::Force),
    "FORCE_INDEX" => CockroachToken::Keyword(Keyword::ForceIndex),
    "FORCE_ZIGZAG" => CockroachToken::Keyword(Keyword::ForceZigzag),
    "FORWARD" => CockroachToken::Keyword(Keyword::Forward),
    "FREEZE" => CockroachToken::Keyword(Keyword::Freeze),
    "FUNCTION" => CockroachToken::Keyword(Keyword::Function),
    "FUNCTIONS" => CockroachToken::Keyword(Keyword::Functions),
    "GENERATED" => CockroachToken::Keyword(Keyword::Generated),
    "GEOMETRYM" => CockroachToken::Keyword(Keyword::Geometrym),
    "GEOMETRYZ" => CockroachToken::Keyword(Keyword::Geometryz),
    "GEOMETRYZM" => CockroachToken::Keyword(Keyword::Geometryzm),
    "GEOMETRYCOLLECTION" => CockroachToken::Keyword(Keyword::Geometrycollection),
    "GEOMETRYCOLLECTIONM" => CockroachToken::Keyword(Keyword::Geometrycollectionm),
    "GEOMETRYCOLLECTIONZ" => CockroachToken::Keyword(Keyword::Geometrycollectionz),
    "GEOMETRYCOLLECTIONZM" => CockroachToken::Keyword(Keyword::Geometrycollectionzm),
    "GLOBAL" => CockroachToken::Keyword(Keyword::Global),
    "GROUPS" => CockroachToken::Keyword(Keyword::Groups),
    "HASH" => CockroachToken::Keyword(Keyword::Hash),
    "HEADER" => CockroachToken::Keyword(Keyword::Header),
    "HIGH" => CockroachToken::Keyword(Keyword::High),
    "HISTOGRAM" => CockroachToken::Keyword(Keyword::Histogram),
    "HOUR" => CockroachToken::Keyword(Keyword::Hour),
    "IDENTITY" => CockroachToken::Keyword(Keyword::Identity),
    "IMMEDIATE" => CockroachToken::Keyword(Keyword::Immediate),
    "INCLUDE" => CockroachToken::Keyword(Keyword::Include),
    "INCLUDING" => CockroachToken::Keyword(Keyword::Including),
    "INCREMENT" => CockroachToken::Keyword(Keyword::Increment),
    "INCREMENTAL_LOCATION" => CockroachToken::Keyword(Keyword::IncrementalLocation),
    "INHERITS" => CockroachToken::Keyword(Keyword::Inherits),
    "INJECT" => CockroachToken::Keyword(Keyword::Inject),
    "INTO_DB" => CockroachToken::Keyword(Keyword::IntoDb),
    "INVERTED" => CockroachToken::Keyword(Keyword::Inverted),
    "ISOLATION" => CockroachToken::Keyword(Keyword::Isolation),
    "JSON" => CockroachToken::Keyword(Keyword::Json),
    "KEY" => CockroachToken::Keyword(Keyword::Key),
    "KMS" => CockroachToken::Keyword(Keyword::Kms),
    "LANGUAGE" => CockroachToken::Keyword(Keyword::Language),
    "LC_COLLATE" => CockroachToken::Keyword(Keyword::LcCollate),
    "LC_CTYPE" => CockroachToken::Keyword(Keyword::LcCtype),
    "LEASE" => CockroachToken::Keyword(Keyword::Lease),
    "LESS" => CockroachToken::Keyword(Keyword::Less),
    "LEVEL" => CockroachToken::Keyword(Keyword::Level),
    "LINESTRING" => CockroachToken::Keyword(Keyword::Linestring),
    "LINESTRINGM" => CockroachToken::Keyword(Keyword::Linestringm),
    "LINESTRINGZ" => CockroachToken::Keyword(Keyword::Linestringz),
    "LINESTRINGZM" => CockroachToken::Keyword(Keyword::Linestringzm),
    "LIST" => CockroachToken::Keyword(Keyword::List),
    "LOCKED" => CockroachToken::Keyword(Keyword::Locked),
    "LOGIN" => CockroachToken::Keyword(Keyword::Login),
    "LOOKUP" => CockroachToken::Keyword(Keyword::Lookup),
    "LOW" => CockroachToken::Keyword(Keyword::Low),
    "MATCH" => CockroachToken::Keyword(Keyword::Match),
    "MAXVALUE" => CockroachToken::Keyword(Keyword::Maxvalue),
    "MERGE" => CockroachToken::Keyword(Keyword::Merge),
    "METHOD" => CockroachToken::Keyword(Keyword::Method),
    "MINUTE" => CockroachToken::Keyword(Keyword::Minute),
    "MINVALUE" => CockroachToken::Keyword(Keyword::Minvalue),
    "MODIFYCLUSTERSETTING" => CockroachToken::Keyword(Keyword::Modifyclustersetting),
    "MULTILINESTRING" => CockroachToken::Keyword(Keyword::Multilinestring),
    "MULTILINESTRINGM" => CockroachToken::Keyword(Keyword::Multilinestringm),
    "MULTILINESTRINGZ" => CockroachToken::Keyword(Keyword::Multilinestringz),
    "MULTILINESTRINGZM" => CockroachToken::Keyword(Keyword::Multilinestringzm),
    "MULTIPOINT" => CockroachToken::Keyword(Keyword::Multipoint),
    "MULTIPOINTM" => CockroachToken::Keyword(Keyword::Multipointm),
    "MULTIPOINTZ" => CockroachToken::Keyword(Keyword::Multipointz),
    "MULTIPOINTZM" => CockroachToken::Keyword(Keyword::Multipointzm),
    "MULTIPOLYGON" => CockroachToken::Keyword(Keyword::Multipolygon),
    "MULTIPOLYGONM" => CockroachToken::Keyword(Keyword::Multipolygonm),
    "MULTIPOLYGONZ" => CockroachToken::Keyword(Keyword::Multipolygonz),
    "MULTIPOLYGONZM" => CockroachToken::Keyword(Keyword::Multipolygonzm),
    "MONTH" => CockroachToken::Keyword(Keyword::Month),
    "NAMES" => CockroachToken::Keyword(Keyword::Names),
    "NAN" => CockroachToken::Keyword(Keyword::Nan),
    "NEVER" => CockroachToken::Keyword(Keyword::Never),
    "NEW_DB_NAME" => CockroachToken::Keyword(Keyword::NewDbName),
    "NEW_KMS" => CockroachToken::Keyword(Keyword::NewKms),
    "NEXT" => CockroachToken::Keyword(Keyword::Next),
    "NORMAL" => CockroachToken::Keyword(Keyword::Normal),
    "NO_INDEX_JOIN" => CockroachToken::Keyword(Keyword::NoIndexJoin),
    "NO_ZIGZAG_JOIN" => CockroachToken::Keyword(Keyword::NoZigzagJoin),
    "NO_FULL_SCAN" => CockroachToken::Keyword(Keyword::NoFullScan),
    "NOCREATEDB" => CockroachToken::Keyword(Keyword::Nocreatedb),
    "NOCREATELOGIN" => CockroachToken::Keyword(Keyword::Nocreatelogin),
    "NOCANCELQUERY" => CockroachToken::Keyword(Keyword::Nocancelquery),
    "NOCREATEROLE" => CockroachToken::Keyword(Keyword::Nocreaterole),
    "NOCONTROLCHANGEFEED" => CockroachToken::Keyword(Keyword::Nocontrolchangefeed),
    "NOCONTROLJOB" => CockroachToken::Keyword(Keyword::Nocontroljob),
    "NOLOGIN" => CockroachToken::Keyword(Keyword::Nologin),
    "NOMODIFYCLUSTERSETTING" => CockroachToken::Keyword(Keyword::Nomodifyclustersetting),
    "NONVOTERS" => CockroachToken::Keyword(Keyword::Nonvoters),
    "NOSQLLOGIN" => CockroachToken::Keyword(Keyword::Nosqllogin),
    "NOVIEWACTIVITY" => CockroachToken::Keyword(Keyword::Noviewactivity),
    "NOVIEWACTIVITYREDACTED" => CockroachToken::Keyword(Keyword::Noviewactivityredacted),
    "NOVIEWCLUSTERSETTING" => CockroachToken::Keyword(Keyword::Noviewclustersetting),
    "NOWAIT" => CockroachToken::Keyword(Keyword::Nowait),
    "NULLS" => CockroachToken::Keyword(Keyword::Nulls),
    "IGNORE_FOREIGN_KEYS" => CockroachToken::Keyword(Keyword::IgnoreForeignKeys),
    "OFF" => CockroachToken::Keyword(Keyword::Off),
    "OIDS" => CockroachToken::Keyword(Keyword::Oids),
    "OLD_KMS" => CockroachToken::Keyword(Keyword::OldKms),
    "OPERATOR" => CockroachToken::Keyword(Keyword::Operator),
    "OPT" => CockroachToken::Keyword(Keyword::Opt),
    "ORDINALITY" => CockroachToken::Keyword(Keyword::Ordinality),
    "OTHERS" => CockroachToken::Keyword(Keyword::Others),
    "OVER" => CockroachToken::Keyword(Keyword::Over),
    "OWNER" => CockroachToken::Keyword(Keyword::Owner),
    "PARENT" => CockroachToken::Keyword(Keyword::Parent),
    "PARTIAL" => CockroachToken::Keyword(Keyword::Partial),
    "PASSWORD" => CockroachToken::Keyword(Keyword::Password),
    "PAUSED" => CockroachToken::Keyword(Keyword::Paused),
    "PHYSICAL" => CockroachToken::Keyword(Keyword::Physical),
    "PLACEMENT" => CockroachToken::Keyword(Keyword::Placement),
    "PLAN" => CockroachToken::Keyword(Keyword::Plan),
    "PLANS" => CockroachToken::Keyword(Keyword::Plans),
    "POINTM" => CockroachToken::Keyword(Keyword::Pointm),
    "POINTZ" => CockroachToken::Keyword(Keyword::Pointz),
    "POINTZM" => CockroachToken::Keyword(Keyword::Pointzm),
    "POLYGONM" => CockroachToken::Keyword(Keyword::Polygonm),
    "POLYGONZ" => CockroachToken::Keyword(Keyword::Polygonz),
    "POLYGONZM" => CockroachToken::Keyword(Keyword::Polygonzm),
    "PRECEDING" => CockroachToken::Keyword(Keyword::Preceding),
    "PRESERVE" => CockroachToken::Keyword(Keyword::Preserve),
    "PRIOR" => CockroachToken::Keyword(Keyword::Prior),
    "PRIORITY" => CockroachToken::Keyword(Keyword::Priority),
    "PUBLIC" => CockroachToken::Keyword(Keyword::Public),
    "PUBLICATION" => CockroachToken::Keyword(Keyword::Publication),
    "QUOTE" => CockroachToken::Keyword(Keyword::Quote),
    "READ" => CockroachToken::Keyword(Keyword::Read),
    "RECURRING" => CockroachToken::Keyword(Keyword::Recurring),
    "RECURSIVE" => CockroachToken::Keyword(Keyword::Recursive),
    "REF" => CockroachToken::Keyword(Keyword::Ref),
    "REGION" => CockroachToken::Keyword(Keyword::Region),
    "REGIONAL" => CockroachToken::Keyword(Keyword::Regional),
    "REINDEX" => CockroachToken::Keyword(Keyword::Reindex),
    "RELOCATE" => CockroachToken::Keyword(Keyword::Relocate),
    "RENAME" => CockroachToken::Keyword(Keyword::Rename),
    "REPEATABLE" => CockroachToken::Keyword(Keyword::Repeatable),
    "REPLACE" => CockroachToken::Keyword(Keyword::Replace),
    "RESTRICTED" => CockroachToken::Keyword(Keyword::Restricted),
    "RETRY" => CockroachToken::Keyword(Keyword::Retry),
    "REVISION_HISTORY" => CockroachToken::Keyword(Keyword::RevisionHistory),
    "ROLE" => CockroachToken::Keyword(Keyword::Role),
    "ROLLUP" => CockroachToken::Keyword(Keyword::Rollup),
    "ROUTINES" => CockroachToken::Keyword(Keyword::Routines),
    "ROWS" => CockroachToken::Keyword(Keyword::Rows),
    "RULE" => CockroachToken::Keyword(Keyword::Rule),
    "RUNNING" => CockroachToken::Keyword(Keyword::Running),
    "SETTINGS" => CockroachToken::Keyword(Keyword::Settings),
    "SCATTER" => CockroachToken::Keyword(Keyword::Scatter),
    "SEARCH" => CockroachToken::Keyword(Keyword::Search),
    "SECOND" => CockroachToken::Keyword(Keyword::Second),
    "SERIALIZABLE" => CockroachToken::Keyword(Keyword::Serializable),
    "SEQUENCE" => CockroachToken::Keyword(Keyword::Sequence),
    "SERVER" => CockroachToken::Keyword(Keyword::Server),
    "SETS" => CockroachToken::Keyword(Keyword::Sets),
    "SHARE" => CockroachToken::Keyword(Keyword::Share),
    "SIMPLE" => CockroachToken::Keyword(Keyword::Simple),
    "SKIP" => CockroachToken::Keyword(Keyword::Skip),
    "SKIP_LOCALITIES_CHECK" => CockroachToken::Keyword(Keyword::SkipLocalitiesCheck),
    "SKIP_MISSING_FOREIGN_KEYS" => CockroachToken::Keyword(Keyword::SkipMissingForeignKeys),
    "SKIP_MISSING_SEQUENCES" => CockroachToken::Keyword(Keyword::SkipMissingSequences),
    "SKIP_MISSING_SEQUENCE_OWNERS" => CockroachToken::Keyword(Keyword::SkipMissingSequenceOwners),
    "SKIP_MISSING_VIEWS" => CockroachToken::Keyword(Keyword::SkipMissingViews),
    "SNAPSHOT" => CockroachToken::Keyword(Keyword::Snapshot),
    "SPLIT" => CockroachToken::Keyword(Keyword::Split),
    "SQL" => CockroachToken::Keyword(Keyword::Sql),
    "SQLLOGIN" => CockroachToken::Keyword(Keyword::Sqllogin),
    "STATEMENTS" => CockroachToken::Keyword(Keyword::Statements),
    "STORAGE" => CockroachToken::Keyword(Keyword::Storage),
    "STORE" => CockroachToken::Keyword(Keyword::Store),
    "STORED" => CockroachToken::Keyword(Keyword::Stored),
    "STORING" => CockroachToken::Keyword(Keyword::Storing),
    "STRICT" => CockroachToken::Keyword(Keyword::Strict),
    "SUBSCRIPTION" => CockroachToken::Keyword(Keyword::Subscription),
    "SURVIVE" => CockroachToken::Keyword(Keyword::Survive),
    "SYNTAX" => CockroachToken::Keyword(Keyword::Syntax),
    "TABLESPACE" => CockroachToken::Keyword(Keyword::Tablespace),
    "TEMP" => CockroachToken::Keyword(Keyword::Temp),
    "TEMPLATE" => CockroachToken::Keyword(Keyword::Template),
    "TEMPORARY" => CockroachToken::Keyword(Keyword::Temporary),
    "TESTING_RELOCATE" => CockroachToken::Keyword(Keyword::TestingRelocate),
    "TEXT" => CockroachToken::Keyword(Keyword::Text),
    "TIES" => CockroachToken::Keyword(Keyword::Ties),
    "TRIGGER" => CockroachToken::Keyword(Keyword::Trigger),
    "TRUSTED" => CockroachToken::Keyword(Keyword::Trusted),
    "THROTTLING" => CockroachToken::Keyword(Keyword::Throttling),
    "UNBOUNDED" => CockroachToken::Keyword(Keyword::Unbounded),
    "UNCOMMITTED" => CockroachToken::Keyword(Keyword::Uncommitted),
    "UNKNOWN" => CockroachToken::Keyword(Keyword::Unknown),
    "UNLOGGED" => CockroachToken::Keyword(Keyword::Unlogged),
    "UNSET" => CockroachToken::Keyword(Keyword::Unset),
    "UNSPLIT" => CockroachToken::Keyword(Keyword::Unsplit),
    "UNTIL" => CockroachToken::Keyword(Keyword::Until),
    "VALID" => CockroachToken::Keyword(Keyword::Valid),
    "VALIDATE" => CockroachToken::Keyword(Keyword::Validate),
    "VALUE" => CockroachToken::Keyword(Keyword::Value),
    "VARYING" => CockroachToken::Keyword(Keyword::Varying),
    "VIEWACTIVITY" => CockroachToken::Keyword(Keyword::Viewactivity),
    "VIEWACTIVITYREDACTED" => CockroachToken::Keyword(Keyword::Viewactivityredacted),
    "VIEWCLUSTERSETTING" => CockroachToken::Keyword(Keyword::Viewclustersetting),
    "VISIBLE" => CockroachToken::Keyword(Keyword::Visible),
    "VOTERS" => CockroachToken::Keyword(Keyword::Voters),
    "WITHIN" => CockroachToken::Keyword(Keyword::Within),
    "WRITE" => CockroachToken::Keyword(Keyword::Write),
    "YEAR" => CockroachToken::Keyword(Keyword::Year),
    "ANNOTATE_TYPE" => CockroachToken::Keyword(Keyword::AnnotateType),
    "BETWEEN" => CockroachToken::Keyword(Keyword::Between),
    "BIGINT" => CockroachToken::Keyword(Keyword::Bigint),
    "BIT" => CockroachToken::Keyword(Keyword::Bit),
    "BOOLEAN" => CockroachToken::Keyword(Keyword::Boolean),
    "BOX2D" => CockroachToken::Keyword(Keyword::Box2d),
    "CHAR" => CockroachToken::Keyword(Keyword::Char),
    "CHARACTER" => CockroachToken::Keyword(Keyword::Character),
    "COALESCE" => CockroachToken::Keyword(Keyword::Coalesce),
    "DEC" => CockroachToken::Keyword(Keyword::Dec),
    "DECIMAL" => CockroachToken::Keyword(Keyword::Decimal),
    "EXTRACT" => CockroachToken::Keyword(Keyword::Extract),
    "EXTRACT_DURATION" => CockroachToken::Keyword(Keyword::ExtractDuration),
    "FLOAT" => CockroachToken::Keyword(Keyword::Float),
    "GEOGRAPHY" => CockroachToken::Keyword(Keyword::Geography),
    "GEOMETRY" => CockroachToken::Keyword(Keyword::Geometry),
    "GREATEST" => CockroachToken::Keyword(Keyword::Greatest),
    "GROUPING" => CockroachToken::Keyword(Keyword::Grouping),
    "IFERROR" => CockroachToken::Keyword(Keyword::Iferror),
    "IFNULL" => CockroachToken::Keyword(Keyword::Ifnull),
    "INT" => CockroachToken::Keyword(Keyword::Int),
    "INTEGER" => CockroachToken::Keyword(Keyword::Integer),
    "INTERVAL" => CockroachToken::Keyword(Keyword::Interval),
    "ISERROR" => CockroachToken::Keyword(Keyword::Iserror),
    "LEAST" => CockroachToken::Keyword(Keyword::Least),
    "NULLIF" => CockroachToken::Keyword(Keyword::Nullif),
    "NUMERIC" => CockroachToken::Keyword(Keyword::Numeric),
    "OUT" => CockroachToken::Keyword(Keyword::Out),
    "OVERLAY" => CockroachToken::Keyword(Keyword::Overlay),
    "POINT" => CockroachToken::Keyword(Keyword::Point),
    "POLYGON" => CockroachToken::Keyword(Keyword::Polygon),
    "POSITION" => CockroachToken::Keyword(Keyword::Position),
    "PRECISION" => CockroachToken::Keyword(Keyword::Precision),
    "REAL" => CockroachToken::Keyword(Keyword::Real),
    "SMALLINT" => CockroachToken::Keyword(Keyword::Smallint),
    "STRING" => CockroachToken::Keyword(Keyword::String),
    "SUBSTRING" => CockroachToken::Keyword(Keyword::Substring),
    "TIME" => CockroachToken::Keyword(Keyword::Time),
    "TIMETZ" => CockroachToken::Keyword(Keyword::Timetz),
    "TIMESTAMP" => CockroachToken::Keyword(Keyword::Timestamp),
    "TIMESTAMPTZ" => CockroachToken::Keyword(Keyword::Timestamptz),
    "TREAT" => CockroachToken::Keyword(Keyword::Treat),
    "TRIM" => CockroachToken::Keyword(Keyword::Trim),
    "VARBIT" => CockroachToken::Keyword(Keyword::Varbit),
    "VARCHAR" => CockroachToken::Keyword(Keyword::Varchar),
    "VIRTUAL" => CockroachToken::Keyword(Keyword::Virtual),
    "WORK" => CockroachToken::Keyword(Keyword::Work),
    "SELECT" => CockroachToken::Keyword(Keyword::Select),
    "USER" => CockroachToken::Keyword(Keyword::User),
    "TRUE" => CockroachToken::Keyword(Keyword::True),
    "FALSE" => CockroachToken::Keyword(Keyword::False),
    "ARRAY" => CockroachToken::Keyword(Keyword::Array),
    "TYPEANNOTATE" => CockroachToken::Keyword(Keyword::Typeannotate),
    "COLLATE" => CockroachToken::Keyword(Keyword::Collate),
    "JSON_SOME_EXISTS" => CockroachToken::Keyword(Keyword::JsonSomeExists),
    "JSON_ALL_EXISTS" => CockroachToken::Keyword(Keyword::JsonAllExists),
    "CONTAINS" => CockroachToken::Keyword(Keyword::Contains),
    "CONTAINED_BY" => CockroachToken::Keyword(Keyword::ContainedBy),
    "FETCHVAL" => CockroachToken::Keyword(Keyword::Fetchval),
    "FETCHTEXT" => CockroachToken::Keyword(Keyword::Fetchtext),
    "FETCHVAL_PATH" => CockroachToken::Keyword(Keyword::FetchvalPath),
    "FETCHTEXT_PATH" => CockroachToken::Keyword(Keyword::FetchtextPath),
    "REMOVE_PATH" => CockroachToken::Keyword(Keyword::RemovePath),
    "OR" => CockroachToken::Keyword(Keyword::Or),
    "LIKE" => CockroachToken::Keyword(Keyword::Like),
    "ILIKE" => CockroachToken::Keyword(Keyword::Ilike),
    "SIMILAR" => CockroachToken::Keyword(Keyword::Similar),
    "ISNULL" => CockroachToken::Keyword(Keyword::Isnull),
    "NOTNULL" => CockroachToken::Keyword(Keyword::Notnull),
    "DISTINCT" => CockroachToken::Keyword(Keyword::Distinct),
    "SYMMETRIC" => CockroachToken::Keyword(Keyword::Symmetric),
    "AUTHORIZATION" => CockroachToken::Keyword(Keyword::Authorization),
    "ORDER" => CockroachToken::Keyword(Keyword::Order),
    "LIMIT" => CockroachToken::Keyword(Keyword::Limit),
    "ONLY" => CockroachToken::Keyword(Keyword::Only),
    "ASYMMETRIC" => CockroachToken::Keyword(Keyword::Asymmetric),
    "ANY" => CockroachToken::Keyword(Keyword::Any),
    "SOME" => CockroachToken::Keyword(Keyword::Some),
    "UNIQUE" => CockroachToken::Keyword(Keyword::Unique),
    "USING" => CockroachToken::Keyword(Keyword::Using),
    "FAMILY" => CockroachToken::Keyword(Keyword::Family),
    "UNION" => CockroachToken::Keyword(Keyword::Union),
    "INTERSECT" => CockroachToken::Keyword(Keyword::Intersect),
    "EXCEPT" => CockroachToken::Keyword(Keyword::Except),
    "OFFSET" => CockroachToken::Keyword(Keyword::Offset),
    "LATERAL" => CockroachToken::Keyword(Keyword::Lateral),
    "ASC" => CockroachToken::Keyword(Keyword::Asc),
    "BOTH" => CockroachToken::Keyword(Keyword::Both),
    "CASE" => CockroachToken::Keyword(Keyword::Case),
    "CAST" => CockroachToken::Keyword(Keyword::Cast),
    "CHECK" => CockroachToken::Keyword(Keyword::Check),
    "CURRENT_CATALOG" => CockroachToken::Keyword(Keyword::CurrentCatalog),
    "CURRENT_DATE" => CockroachToken::Keyword(Keyword::CurrentDate),
    "CURRENT_ROLE" => CockroachToken::Keyword(Keyword::CurrentRole),
    "CURRENT_SCHEMA" => CockroachToken::Keyword(Keyword::CurrentSchema),
    "CURRENT_TIME" => CockroachToken::Keyword(Keyword::CurrentTime),
    "CURRENT_TIMESTAMP" => CockroachToken::Keyword(Keyword::CurrentTimestamp),
    "DEFERRABLE" => CockroachToken::Keyword(Keyword::Deferrable),
    "DESC" => CockroachToken::Keyword(Keyword::Desc),
    "ELSE" => CockroachToken::Keyword(Keyword::Else),
    "FOREIGN" => CockroachToken::Keyword(Keyword::Foreign),
    "GROUP" => CockroachToken::Keyword(Keyword::Group),
    "HAVING" => CockroachToken::Keyword(Keyword::Having),
    "INITIALLY" => CockroachToken::Keyword(Keyword::Initially),
    "LEADING" => CockroachToken::Keyword(Keyword::Leading),
    "LOCALTIME" => CockroachToken::Keyword(Keyword::Localtime),
    "LOCALTIMESTAMP" => CockroachToken::Keyword(Keyword::Localtimestamp),
    "PLACING" => CockroachToken::Keyword(Keyword::Placing),
    "PRIMARY" => CockroachToken::Keyword(Keyword::Primary),
    "REFERENCES" => CockroachToken::Keyword(Keyword::References),
    "THEN" => CockroachToken::Keyword(Keyword::Then),
    "TRAILING" => CockroachToken::Keyword(Keyword::Trailing),
    "VARIADIC" => CockroachToken::Keyword(Keyword::Variadic),
    "WINDOW" => CockroachToken::Keyword(Keyword::Window),
    "COLLATION" => CockroachToken::Keyword(Keyword::Collation),
    "CROSS" => CockroachToken::Keyword(Keyword::Cross),
    "JOIN" => CockroachToken::Keyword(Keyword::Join),
    "NATURAL" => CockroachToken::Keyword(Keyword::Natural),
    "INNER" => CockroachToken::Keyword(Keyword::Inner),
    "LEFT" => CockroachToken::Keyword(Keyword::Left),
    "NONE" => CockroachToken::Keyword(Keyword::None),
    "OUTER" => CockroachToken::Keyword(Keyword::Outer),
    "OVERLAPS" => CockroachToken::Keyword(Keyword::Overlaps),
    "RIGHT" => CockroachToken::Keyword(Keyword::Right),
    "DATE" => CockroachToken::Keyword(Keyword::Date),
    "GENERATED_ALWAYS" => CockroachToken::Keyword(Keyword::GeneratedAlways),
    "GENERATED_BY_DEFAULT" => CockroachToken::Keyword(Keyword::GeneratedByDefault)
};

// And today's award for strangest code goes to...
impl PartialEq for CockroachToken {
    fn eq(&self, other: &Self) -> bool {
        match self {
            CockroachToken::UnknownToken(u1) => match other {
                CockroachToken::UnknownToken(u2) => u1 == u2,
                _ => false,
            },
            CockroachToken::Identifier(i1) => match other {
                CockroachToken::Identifier(i2) => i1 == i2,
                _ => false,
            },
            CockroachToken::Const(_) => match other {
                CockroachToken::Const(_) => true,
                _ => false,
            },
            CockroachToken::SingleQuote => match other {
                CockroachToken::SingleQuote => true,
                _ => false,
            },
            CockroachToken::DoubleQuote => match other {
                CockroachToken::DoubleQuote => true,
                _ => false,
            },
            CockroachToken::DollarQuote(id1) => match other {
                CockroachToken::DollarQuote(id2) => id1 == id2,
                _ => false,
            },
            CockroachToken::Placeholder(p1) => match other {
                CockroachToken::Placeholder(p2) => p1 == p2,
                _ => false,
            },
            CockroachToken::Keyword(k1) => match other {
                CockroachToken::Keyword(k2) => k1 == k2,
                _ => false,
            },
            CockroachToken::LineComment => match other {
                CockroachToken::LineComment => true,
                _ => false,
            },
            CockroachToken::BlockCommentOpen => match other {
                CockroachToken::BlockCommentOpen => true,
                _ => false,
            },
            CockroachToken::BlockCommentClose => match other {
                CockroachToken::BlockCommentClose => true,
                _ => false,
            },
            CockroachToken::Comment(s1) => match other {
                CockroachToken::Comment(s2) => s1 == s2,
                _ => false,
            },
            CockroachToken::Symbol(c1) => match other {
                CockroachToken::Symbol(c2) => c1 == c2,
                _ => false,
            },
            CockroachToken::Whitespace(c1) => match other {
                CockroachToken::Whitespace(c2) => c1 == c2,
                _ => false,
            },
        }
    }
}

impl Eq for CockroachToken {}

// TODO: use `derivative` crate?
impl Hash for CockroachToken {
    fn hash<H: Hasher>(&self, state: &mut H) {
        match self {
            CockroachToken::UnknownToken(c) => {
                state.write_u8(1);
                c.hash(state);
            }
            CockroachToken::Whitespace(c) => {
                state.write_u8(2);
                c.hash(state);
            }
            CockroachToken::Identifier(s) => {
                state.write_u8(3);
                s.hash(state);
            }
            CockroachToken::Const(_) => {
                state.write_u8(4);
                // Don't want to hash this--use deep_eq instead
            }
            CockroachToken::SingleQuote => {
                state.write_u8(5);
            }
            CockroachToken::DollarQuote(id) => {
                state.write_u8(6);
                id.hash(state);
            }
            CockroachToken::BlockCommentOpen => {
                state.write_u8(7);
            }
            CockroachToken::BlockCommentClose => {
                state.write_u8(8);
            }
            CockroachToken::Comment(s) => {
                state.write_u8(9);
                s.hash(state);
            }
            CockroachToken::Placeholder(s) => {
                state.write_u8(10);
                s.hash(state);
            }
            CockroachToken::Keyword(k) => {
                state.write_u8(11);
                k.hash(state);
            }
            CockroachToken::Symbol(s) => {
                state.write_u8(12);
                s.hash(state);
            }
            CockroachToken::LineComment => {
                state.write_u8(13);
            }
            CockroachToken::DoubleQuote => {
                state.write_u8(14);
            }
        };
    }
}

impl Display for CockroachToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CockroachToken::UnknownToken(c)
            | CockroachToken::Whitespace(c)
            | CockroachToken::Symbol(c) => write!(f, "{}", c),
            CockroachToken::Identifier(s) => write!(f, "{}", s),
            CockroachToken::SingleQuote => write!(f, "'"),
            CockroachToken::DoubleQuote => write!(f, "\""),
            CockroachToken::DollarQuote(id) => write!(f, "${}$", id),
            CockroachToken::Const(s) => write!(f, "{}", s),
            CockroachToken::Placeholder(s) => write!(f, "{}", s),
            CockroachToken::LineComment => write!(f, "--"),
            CockroachToken::BlockCommentOpen => write!(f, "/*"),
            CockroachToken::BlockCommentClose => write!(f, "*/"),
            CockroachToken::Comment(s) => write!(f, "{}", s),
            CockroachToken::Keyword(k) => write!(f, "{}", k),
        }
    }
}

impl Token for CockroachToken {
    fn scan_forward(query: &str) -> Vec<(Self, usize)> {
        Self::scan_with_parameters(query, ScanDirection::Forward)
    }

    fn scan_reverse(query: &str) -> Vec<(Self, usize)> {
        Self::scan_with_parameters(query, ScanDirection::Reverse)
    }

    fn deep_eq(&self, other: &Self) -> bool {
        (self == other)
            && match (self, other) {
                (CockroachToken::Const(s1), CockroachToken::Const(s2)) => s1 == s2,
                _ => true,
            }
    }

    // TODO: IF we don't enforce the contents of any of these tokens, why not just merge them into one token type?
    // That way, we can remove the whole hashmap difficulties we see in matcher.rs and the algorithm becomes guaranteed O(n)
    fn is_param_token(&self) -> bool {
        match self {
            CockroachToken::Const(_) => true,
            _ => false,
        }
    }

    fn is_whitespace(&self) -> bool {
        match self {
            CockroachToken::Whitespace(_) => true,
            _ => false,
        }
    }
}

impl CockroachToken {
    fn scan_without_parameters(query: &str) -> Vec<Self> {
        let mut iter = query.chars().peekable();
        let mut tokens = vec![];

        while let Some(c) = iter.next() {
            tokens.push(match (c, iter.peek()) {
                ('-', Some('-')) => {
                    iter.next(); // consume '-'
                    CockroachToken::LineComment
                }
                ('/', Some('*')) => {
                    iter.next(); // consume '*'
                    CockroachToken::BlockCommentOpen
                }
                ('*', Some('/')) => {
                    iter.next(); // consume '/'
                    CockroachToken::BlockCommentClose
                }
                ('\'', _) => CockroachToken::SingleQuote,
                ('"', _) => CockroachToken::DoubleQuote,
                ('.', Some('0'..='9')) => match_fconst_period(&mut iter, vec!['.']),
                ('$', Some('0'..='9')) => match_placeholder(&mut iter),
                ('$', Some(_)) => match_dollar_opening(&mut iter),
                ('$', None) => CockroachToken::UnknownToken(c),
                ('_', _) => match_kw_id(&mut iter, vec!['_']),
                (
                    '/' | '-' | '^' | ';' | '(' | ')' | '@' | ',' | '=' | '*' | '+' | '~' | '%'
                    | '#' | '&' | '|' | '<' | '>' | '?' | '[' | ']' | '{' | '}' | ':' | '.',
                    _,
                ) => CockroachToken::Symbol(c),
                (' ' | '\t' | '\r' | '\n', _) => CockroachToken::Whitespace(c),
                ('0', Some('x')) => {
                    iter.next();
                    match_iconst_0x(&mut iter)
                }
                ('0'..='9', _) => match_const_digit(&mut iter, vec![c]),
                // "SQL identifiers and key words must begin with a letter (a-z, but also letters with diacritical marks and non-Latin letters), or an underscore"
                (c, _) if c.is_alphabetic() => match_kw_id(&mut iter, vec![c.to_ascii_uppercase()]),
                // Not alphanumeric, and not any of the special chars we listed above: must be a Weasley
                (c, _) => CockroachToken::UnknownToken(c),
            });
        }

        tokens
    }

    /// Takes any instances of quoted parameters (such as apostraphe-quoted, like 'param', or dollar-quoted, like $$param$$ or $label$param$label$) and condenses their contents into a single 'Const' token.
    ///
    /// This function also condenses block comments and line comments.
    /// It takes into account all nesting rules related to comments and parameters in PostgreSQL.
    fn scan_with_parameters(query: &str, direction: ScanDirection) -> Vec<(Self, usize)> {
        // First, scan tokens without accounting for any quoted or commented-out portions
        let mut tokens = CockroachToken::scan_without_parameters(query);
        if tokens.len() == 0 {
            return Vec::new();
        }

        let mut norm_tokens = Vec::new();
        let mut layers = Vec::new();
        let mut contents: Option<String> = None;
        let (indices, last_idx) = if direction == ScanDirection::Forward {
            (0..=(tokens.len() - 1), tokens.len() - 1)
        } else {
            tokens.reverse();
            ((tokens.len() - 1)..=0, 0)
        };

        let mut iter = indices.zip(tokens.into_iter()).peekable();
        while let Some((idx, next_token)) = iter.next() {
            if let Some(top_layer) = layers.last() {
                match (top_layer, &next_token) {
                    (CockroachToken::BlockCommentOpen, CockroachToken::BlockCommentClose)
                    | (CockroachToken::BlockCommentClose, CockroachToken::BlockCommentOpen)
                    | (CockroachToken::SingleQuote, CockroachToken::SingleQuote) => {
                        layers.pop();
                    }
                    (CockroachToken::DoubleQuote, CockroachToken::DoubleQuote) => {
                        if let Some((_, CockroachToken::DoubleQuote)) = iter.peek() {
                            iter.next();
                            match contents.as_mut() {
                                Some(param) => param.push_str("\""),
                                None => contents = Some("\"".to_string()),
                            }
                        }
                        layers.pop();
                    }
                    (CockroachToken::DollarQuote(d1), CockroachToken::DollarQuote(d2))
                        if d1 == d2 =>
                    {
                        layers.pop();
                    }
                    (CockroachToken::DollarQuote(_), CockroachToken::DollarQuote(_)) => {
                        layers.push(next_token.clone())
                    } // Dollar quoting can be nested
                    (CockroachToken::BlockCommentOpen, CockroachToken::BlockCommentOpen)
                    | (CockroachToken::BlockCommentClose, CockroachToken::BlockCommentClose) => {
                        layers.push(next_token.clone())
                    } // Block comments can also be nested
                    _ => (),
                }

                if layers.is_empty() {
                    norm_tokens.push((
                        match &next_token {
                            CockroachToken::BlockCommentOpen
                            | CockroachToken::BlockCommentClose => {
                                CockroachToken::Comment(contents.unwrap_or(String::new()))
                            }
                            _ => CockroachToken::Const(contents.unwrap_or(String::new())),
                        },
                        match direction {
                            ScanDirection::Forward => idx - 1,
                            ScanDirection::Reverse => idx + 1,
                        },
                    ));
                    norm_tokens.push((next_token, idx));
                    contents = None;
                } else {
                    match contents.as_mut() {
                        Some(param) => param.push_str(next_token.to_string().as_str()),
                        None => contents = Some(next_token.to_string()),
                    }
                }
            } else {
                match &next_token {
                    CockroachToken::SingleQuote
                    | CockroachToken::DollarQuote(_)
                    | CockroachToken::DoubleQuote
                    | CockroachToken::LineComment => layers.push(next_token.clone()),
                    CockroachToken::BlockCommentOpen if direction == ScanDirection::Forward => {
                        layers.push(next_token.clone())
                    }
                    CockroachToken::BlockCommentClose if direction == ScanDirection::Reverse => {
                        layers.push(next_token.clone())
                    }
                    _ => (),
                }
                norm_tokens.push((next_token, idx));
            }
        }

        // If there was no closing quote or comment, or if there was a line comment, then just output the Const/Identifier/Comment anyway
        match layers.first() {
            Some(CockroachToken::SingleQuote | CockroachToken::DollarQuote(_)) => {
                norm_tokens.push((
                    CockroachToken::Const(contents.unwrap_or(String::new())),
                    last_idx,
                ))
            }
            Some(CockroachToken::DoubleQuote) => norm_tokens.push((
                CockroachToken::Identifier(contents.unwrap_or(String::new())),
                last_idx,
            )),
            Some(_) => norm_tokens.push((
                CockroachToken::Comment(contents.unwrap_or(String::new())),
                last_idx,
            )),
            None => (),
        }

        norm_tokens
    }
}

fn match_kw_id(
    iter: &mut std::iter::Peekable<std::str::Chars>,
    mut chars: Vec<char>,
) -> CockroachToken {
    while let Some(p) = iter.peek() {
        if !p.is_alphabetic() && !p.is_ascii_digit() && *p != '_' && *p != '$' {
            break;
        }
        chars.push(p.to_ascii_uppercase());
        iter.next();
    }

    let identifier = chars.into_iter().collect::<String>();
    match KEYWORDS.get(&identifier) {
        Some(token) => token.clone(),
        None => CockroachToken::Identifier(identifier),
    }
}

fn match_iconst_0x(iter: &mut std::iter::Peekable<std::str::Chars>) -> CockroachToken {
    let mut chars = vec!['0', 'x'];

    while let Some(n @ ('0'..='9' | 'a'..='f' | 'A'..='F')) = iter.peek() {
        chars.push(n.clone());
        iter.next();
    }

    CockroachToken::Const(chars.into_iter().collect::<String>())
}

fn match_fconst_period(
    iter: &mut std::iter::Peekable<std::str::Chars>,
    mut chars: Vec<char>,
) -> CockroachToken {
    while let Some(p) = iter.peek().copied() {
        match p {
            '0'..='9' => {
                chars.push(p);
                iter.next();
            }
            'e' => {
                chars.push(p);
                iter.next();
                match iter.peek() {
                    Some(sign @ ('+' | '-')) => {
                        chars.push(sign.clone());
                        iter.next();
                        return match_fconst_e(iter, chars);
                    }
                    Some('0'..='9') => return match_fconst_e(iter, chars),
                    Some(_) | None => break,
                };
            }
            _ => break,
        };
    }

    CockroachToken::Const(chars.into_iter().collect::<String>())
}

fn match_fconst_e(
    iter: &mut std::iter::Peekable<std::str::Chars>,
    mut chars: Vec<char>,
) -> CockroachToken {
    while let Some(p @ '0'..='9') = iter.peek() {
        chars.push(p.clone());
        iter.next();
    }

    CockroachToken::Const(chars.into_iter().collect::<String>())
}

fn match_placeholder(iter: &mut std::iter::Peekable<std::str::Chars>) -> CockroachToken {
    let mut chars: Vec<char> = vec![];

    while let Some(p @ ('0'..='9')) = iter.peek() {
        chars.push(p.clone());
        iter.next();
    }

    CockroachToken::Placeholder(chars.into_iter().collect::<String>())
}

fn match_dollar_opening(iter: &mut std::iter::Peekable<std::str::Chars>) -> CockroachToken {
    let mut ident = vec![];
    while let Some(p @ ('a'..='z' | 'A'..='Z' | '0'..='9' | '_')) = iter.peek() {
        ident.push(p.clone());
        iter.next();
    }

    match iter.peek() {
        Some('$') => {
            iter.next();
            /* match_dollar_sconst(iter, ident.into_iter().collect::<String>()) */
            CockroachToken::DollarQuote(ident.into_iter().collect::<String>())
        }
        _ => CockroachToken::Placeholder(ident.into_iter().collect::<String>()), // TODO: this IS an invalid placeholder
    }
}

fn match_const_digit(
    iter: &mut std::iter::Peekable<std::str::Chars>,
    mut chars: Vec<char>,
) -> CockroachToken {
    while let Some(p @ '0'..='9') = iter.peek() {
        chars.push(p.clone());
        iter.next();
    }

    return match iter.peek() {
        Some('.') => {
            chars.push('.');
            match_fconst_period(iter, chars)
        }
        Some(_) | None => CockroachToken::Const(chars.into_iter().collect::<String>()),
    };
}
