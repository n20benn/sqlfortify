use phf::{Map,phf_map};
use super::token::SqlToken;

// Currently just a clone of CockroachToken

#[derive(Hash, Clone, Debug)]
pub enum PostgresToken {
	UnknownToken(char),
    Identifier(String),
    Sconst(String),
    Bconst(String),
    Bitconst(String),
    Iconst(String),
    Fconst(String),
    Placeholder(String),
    Keyword(Keyword),
	Symbol(char),
	LineComment(String),
	BlockComment(String),
	Whitespace(char),
}

// These are all accepted keywords
#[derive(PartialEq, Eq, Hash, Clone, Debug)]
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


static KEYWORDS: phf::Map<&'static str, PostgresToken> = phf_map! {
	"ANALYZE" => PostgresToken::Keyword(Keyword::Analyze),
	"ANALYSE" => PostgresToken::Keyword(Keyword::Analyse),
	"COPY" => PostgresToken::Keyword(Keyword::Copy),
	"FROM" => PostgresToken::Keyword(Keyword::From),
	"STDIN" => PostgresToken::Keyword(Keyword::Stdin),
	"COMMENT" => PostgresToken::Keyword(Keyword::Comment),
	"ON" => PostgresToken::Keyword(Keyword::On),
	"DATABASE" => PostgresToken::Keyword(Keyword::Database),
	"IS" => PostgresToken::Keyword(Keyword::Is),
	"SCHEMA" => PostgresToken::Keyword(Keyword::Schema),
	"TABLE" => PostgresToken::Keyword(Keyword::Table),
	"COLUMN" => PostgresToken::Keyword(Keyword::Column),
	"INDEX" => PostgresToken::Keyword(Keyword::Index),
	"CONSTRAINT" => PostgresToken::Keyword(Keyword::Constraint),
	"EXECUTE" => PostgresToken::Keyword(Keyword::Execute),
	"DEALLOCATE" => PostgresToken::Keyword(Keyword::Deallocate),
	"PREPARE" => PostgresToken::Keyword(Keyword::Prepare),
	"ALL" => PostgresToken::Keyword(Keyword::All),
	"DISCARD" => PostgresToken::Keyword(Keyword::Discard),
	"GRANT" => PostgresToken::Keyword(Keyword::Grant),
	"TO" => PostgresToken::Keyword(Keyword::To),
	"WITH" => PostgresToken::Keyword(Keyword::With),
	"ADMIN" => PostgresToken::Keyword(Keyword::Admin),
	"OPTION" => PostgresToken::Keyword(Keyword::Option),
	"TYPE" => PostgresToken::Keyword(Keyword::Type),
	"TABLES" => PostgresToken::Keyword(Keyword::Tables),
	"IN" => PostgresToken::Keyword(Keyword::In),
	"AS" => PostgresToken::Keyword(Keyword::As),
	"REVOKE" => PostgresToken::Keyword(Keyword::Revoke),
	"FOR" => PostgresToken::Keyword(Keyword::For),
	"SAVEPOINT" => PostgresToken::Keyword(Keyword::Savepoint),
	"REASSIGN" => PostgresToken::Keyword(Keyword::Reassign),
	"OWNED" => PostgresToken::Keyword(Keyword::Owned),
	"BY" => PostgresToken::Keyword(Keyword::By),
	"DROP" => PostgresToken::Keyword(Keyword::Drop),
	"RELEASE" => PostgresToken::Keyword(Keyword::Release),
	"REFRESH" => PostgresToken::Keyword(Keyword::Refresh),
	"MATERIALIZED" => PostgresToken::Keyword(Keyword::Materialized),
	"VIEW" => PostgresToken::Keyword(Keyword::View),
	"CLOSE" => PostgresToken::Keyword(Keyword::Close),
	"DECLARE" => PostgresToken::Keyword(Keyword::Declare),
	"CURSOR" => PostgresToken::Keyword(Keyword::Cursor),
	"FETCH" => PostgresToken::Keyword(Keyword::Fetch),
	"MOVE" => PostgresToken::Keyword(Keyword::Move),
	"BACKUP" => PostgresToken::Keyword(Keyword::Backup),
	"INTO" => PostgresToken::Keyword(Keyword::Into),
	"LATEST" => PostgresToken::Keyword(Keyword::Latest),
	"DELETE" => PostgresToken::Keyword(Keyword::Delete),
	"EXPLAIN" => PostgresToken::Keyword(Keyword::Explain),
	"IMPORT" => PostgresToken::Keyword(Keyword::Import),
	"DATA" => PostgresToken::Keyword(Keyword::Data),
	"INSERT" => PostgresToken::Keyword(Keyword::Insert),
	"RESTORE" => PostgresToken::Keyword(Keyword::Restore),
	"SYSTEM" => PostgresToken::Keyword(Keyword::System),
	"USERS" => PostgresToken::Keyword(Keyword::Users),
	"REPLICATION" => PostgresToken::Keyword(Keyword::Replication),
	"STREAM" => PostgresToken::Keyword(Keyword::Stream),
	"EXPORT" => PostgresToken::Keyword(Keyword::Export),
	"TRUNCATE" => PostgresToken::Keyword(Keyword::Truncate),
	"UPDATE" => PostgresToken::Keyword(Keyword::Update),
	"SET" => PostgresToken::Keyword(Keyword::Set),
	"UPSERT" => PostgresToken::Keyword(Keyword::Upsert),
	"NULL" => PostgresToken::Keyword(Keyword::Null),
	"TENANT" => PostgresToken::Keyword(Keyword::Tenant),
	"CURRENT_USER" => PostgresToken::Keyword(Keyword::CurrentUser),
	"SESSION_USER" => PostgresToken::Keyword(Keyword::SessionUser),
	"CASCADE" => PostgresToken::Keyword(Keyword::Cascade),
	"RESTRICT" => PostgresToken::Keyword(Keyword::Restrict),
	"CONCURRENTLY" => PostgresToken::Keyword(Keyword::Concurrently),
	"NO" => PostgresToken::Keyword(Keyword::No),
	"TRANSACTION" => PostgresToken::Keyword(Keyword::Transaction),
	"SESSION" => PostgresToken::Keyword(Keyword::Session),
	"BEGIN" => PostgresToken::Keyword(Keyword::Begin),
	"START" => PostgresToken::Keyword(Keyword::Start),
	"COMMIT" => PostgresToken::Keyword(Keyword::Commit),
	"END" => PostgresToken::Keyword(Keyword::End),
	"ROLLBACK" => PostgresToken::Keyword(Keyword::Rollback),
	"ABORT" => PostgresToken::Keyword(Keyword::Abort),
	"BINARY" => PostgresToken::Keyword(Keyword::Binary),
	"INSENSITIVE" => PostgresToken::Keyword(Keyword::Insensitive),
	"ASENSITIVE" => PostgresToken::Keyword(Keyword::Asensitive),
	"SCROLL" => PostgresToken::Keyword(Keyword::Scroll),
	"HOLD" => PostgresToken::Keyword(Keyword::Hold),
	"WITHOUT" => PostgresToken::Keyword(Keyword::Without),
	"ABSOLUTE" => PostgresToken::Keyword(Keyword::Absolute),
	"RELATIVE" => PostgresToken::Keyword(Keyword::Relative),
	"FIRST" => PostgresToken::Keyword(Keyword::First),
	"LAST" => PostgresToken::Keyword(Keyword::Last),
	"ALTER" => PostgresToken::Keyword(Keyword::Alter),
	"IF" => PostgresToken::Keyword(Keyword::If),
	"EXISTS" => PostgresToken::Keyword(Keyword::Exists),
	"ROLE_ALL" => PostgresToken::Keyword(Keyword::RoleAll),
	"USER_ALL" => PostgresToken::Keyword(Keyword::UserAll),
	"TENANT_ALL" => PostgresToken::Keyword(Keyword::TenantAll),
	"OPTIONS" => PostgresToken::Keyword(Keyword::Options),
	"INCREMENTAL" => PostgresToken::Keyword(Keyword::Incremental),
	"CANCEL" => PostgresToken::Keyword(Keyword::Cancel),
	"JOB" => PostgresToken::Keyword(Keyword::Job),
	"JOBS" => PostgresToken::Keyword(Keyword::Jobs),
	"QUERY" => PostgresToken::Keyword(Keyword::Query),
	"QUERIES" => PostgresToken::Keyword(Keyword::Queries),
	"SESSIONS" => PostgresToken::Keyword(Keyword::Sessions),
	"CREATE" => PostgresToken::Keyword(Keyword::Create),
	"NOT" => PostgresToken::Keyword(Keyword::Not),
	"STATISTICS" => PostgresToken::Keyword(Keyword::Statistics),
	"SCHEDULE" => PostgresToken::Keyword(Keyword::Schedule),
	"CHANGEFEED" => PostgresToken::Keyword(Keyword::Changefeed),
	"EXTENSION" => PostgresToken::Keyword(Keyword::Extension),
	"RETURNING" => PostgresToken::Keyword(Keyword::Returning),
	"NOTHING" => PostgresToken::Keyword(Keyword::Nothing),
	"SCHEDULES" => PostgresToken::Keyword(Keyword::Schedules),
	"DEFAULT" => PostgresToken::Keyword(Keyword::Default),
	"VALUES" => PostgresToken::Keyword(Keyword::Values),
	"CONFLICT" => PostgresToken::Keyword(Keyword::Conflict),
	"DO" => PostgresToken::Keyword(Keyword::Do),
	"PAUSE" => PostgresToken::Keyword(Keyword::Pause),
	"REASON" => PostgresToken::Keyword(Keyword::Reason),
	"RESET" => PostgresToken::Keyword(Keyword::Reset),
	"RESET_ALL" => PostgresToken::Keyword(Keyword::ResetAll),
	"CLUSTER" => PostgresToken::Keyword(Keyword::Cluster),
	"SETTING" => PostgresToken::Keyword(Keyword::Setting),
	"RESUME" => PostgresToken::Keyword(Keyword::Resume),
	"EXPERIMENTAL" => PostgresToken::Keyword(Keyword::Experimental),
	"SCRUB" => PostgresToken::Keyword(Keyword::Scrub),
	"CHARACTERISTICS" => PostgresToken::Keyword(Keyword::Characteristics),
	"LOCAL" => PostgresToken::Keyword(Keyword::Local),
	"USE" => PostgresToken::Keyword(Keyword::Use),
	"SHOW" => PostgresToken::Keyword(Keyword::Show),
	"BACKUPS" => PostgresToken::Keyword(Keyword::Backups),
	"SCHEMAS" => PostgresToken::Keyword(Keyword::Schemas),
	"FILES" => PostgresToken::Keyword(Keyword::Files),
	"RANGES" => PostgresToken::Keyword(Keyword::Ranges),
	"COLUMNS" => PostgresToken::Keyword(Keyword::Columns),
	"CONSTRAINTS" => PostgresToken::Keyword(Keyword::Constraints),
	"TYPES" => PostgresToken::Keyword(Keyword::Types),
	"DATABASES" => PostgresToken::Keyword(Keyword::Databases),
	"ENUMS" => PostgresToken::Keyword(Keyword::Enums),
	"GRANTS" => PostgresToken::Keyword(Keyword::Grants),
	"INDEXES" => PostgresToken::Keyword(Keyword::Indexes),
	"KEYS" => PostgresToken::Keyword(Keyword::Keys),
	"PARTITIONS" => PostgresToken::Keyword(Keyword::Partitions),
	"AUTOMATIC" => PostgresToken::Keyword(Keyword::Automatic),
	"WHEN" => PostgresToken::Keyword(Keyword::When),
	"COMPLETE" => PostgresToken::Keyword(Keyword::Complete),
	"LOCALITY" => PostgresToken::Keyword(Keyword::Locality),
	"RANGE" => PostgresToken::Keyword(Keyword::Range),
	"ROW" => PostgresToken::Keyword(Keyword::Row),
	"REGIONS" => PostgresToken::Keyword(Keyword::Regions),
	"SUPER" => PostgresToken::Keyword(Keyword::Super),
	"SURVIVAL" => PostgresToken::Keyword(Keyword::Survival),
	"GOAL" => PostgresToken::Keyword(Keyword::Goal),
	"ROLES" => PostgresToken::Keyword(Keyword::Roles),
	"STATUS" => PostgresToken::Keyword(Keyword::Status),
	"SEQUENCES" => PostgresToken::Keyword(Keyword::Sequences),
	"TRACE" => PostgresToken::Keyword(Keyword::Trace),
	"KV" => PostgresToken::Keyword(Keyword::Kv),
	"TRANSACTIONS" => PostgresToken::Keyword(Keyword::Transactions),
	"TRANSFER" => PostgresToken::Keyword(Keyword::Transfer),
	"STATE" => PostgresToken::Keyword(Keyword::State),
	"ZONE" => PostgresToken::Keyword(Keyword::Zone),
	"CONFIGURATION" => PostgresToken::Keyword(Keyword::Configuration),
	"PARTITION" => PostgresToken::Keyword(Keyword::Partition),
	"OF" => PostgresToken::Keyword(Keyword::Of),
	"CONFIGURATIONS" => PostgresToken::Keyword(Keyword::Configurations),
	"FULL" => PostgresToken::Keyword(Keyword::Full),
	"SCANS" => PostgresToken::Keyword(Keyword::Scans),
	"PRIVILEGES" => PostgresToken::Keyword(Keyword::Privileges),
	"WHERE" => PostgresToken::Keyword(Keyword::Where),
	"ACTION" => PostgresToken::Keyword(Keyword::Action),
	"ACCESS" => PostgresToken::Keyword(Keyword::Access),
	"ADD" => PostgresToken::Keyword(Keyword::Add),
	"AFTER" => PostgresToken::Keyword(Keyword::After),
	"AGGREGATE" => PostgresToken::Keyword(Keyword::Aggregate),
	"ALWAYS" => PostgresToken::Keyword(Keyword::Always),
	"AT" => PostgresToken::Keyword(Keyword::At),
	"ATTRIBUTE" => PostgresToken::Keyword(Keyword::Attribute),
	"AVAILABILITY" => PostgresToken::Keyword(Keyword::Availability),
	"BACKWARD" => PostgresToken::Keyword(Keyword::Backward),
	"BEFORE" => PostgresToken::Keyword(Keyword::Before),
	"BUCKET_COUNT" => PostgresToken::Keyword(Keyword::BucketCount),
	"BUNDLE" => PostgresToken::Keyword(Keyword::Bundle),
	"CACHE" => PostgresToken::Keyword(Keyword::Cache),
	"CANCELQUERY" => PostgresToken::Keyword(Keyword::Cancelquery),
	"COMMENTS" => PostgresToken::Keyword(Keyword::Comments),
	"COMMITTED" => PostgresToken::Keyword(Keyword::Committed),
	"COMPACT" => PostgresToken::Keyword(Keyword::Compact),
	"COMPLETIONS" => PostgresToken::Keyword(Keyword::Completions),
	"CONFIGURE" => PostgresToken::Keyword(Keyword::Configure),
	"CONNECTION" => PostgresToken::Keyword(Keyword::Connection),
	"CONTROLCHANGEFEED" => PostgresToken::Keyword(Keyword::Controlchangefeed),
	"CONTROLJOB" => PostgresToken::Keyword(Keyword::Controljob),
	"CONVERSION" => PostgresToken::Keyword(Keyword::Conversion),
	"CONVERT" => PostgresToken::Keyword(Keyword::Convert),
	"COVERING" => PostgresToken::Keyword(Keyword::Covering),
	"CREATEDB" => PostgresToken::Keyword(Keyword::Createdb),
	"CREATELOGIN" => PostgresToken::Keyword(Keyword::Createlogin),
	"CREATEROLE" => PostgresToken::Keyword(Keyword::Createrole),
	"CSV" => PostgresToken::Keyword(Keyword::Csv),
	"CUBE" => PostgresToken::Keyword(Keyword::Cube),
	"CURRENT" => PostgresToken::Keyword(Keyword::Current),
	"CYCLE" => PostgresToken::Keyword(Keyword::Cycle),
	"DAY" => PostgresToken::Keyword(Keyword::Day),
	"DEBUG_PAUSE_ON" => PostgresToken::Keyword(Keyword::DebugPauseOn),
	"DEFAULTS" => PostgresToken::Keyword(Keyword::Defaults),
	"DEFERRED" => PostgresToken::Keyword(Keyword::Deferred),
	"DELIMITER" => PostgresToken::Keyword(Keyword::Delimiter),
	"DESTINATION" => PostgresToken::Keyword(Keyword::Destination),
	"DETACHED" => PostgresToken::Keyword(Keyword::Detached),
	"DOMAIN" => PostgresToken::Keyword(Keyword::Domain),
	"DOUBLE" => PostgresToken::Keyword(Keyword::Double),
	"ENCODING" => PostgresToken::Keyword(Keyword::Encoding),
	"ENCRYPTED" => PostgresToken::Keyword(Keyword::Encrypted),
	"ENCRYPTION_PASSPHRASE" => PostgresToken::Keyword(Keyword::EncryptionPassphrase),
	"ENUM" => PostgresToken::Keyword(Keyword::Enum),
	"ESCAPE" => PostgresToken::Keyword(Keyword::Escape),
	"EXCLUDE" => PostgresToken::Keyword(Keyword::Exclude),
	"EXCLUDING" => PostgresToken::Keyword(Keyword::Excluding),
	"EXECUTION" => PostgresToken::Keyword(Keyword::Execution),
	"EXPERIMENTAL_AUDIT" => PostgresToken::Keyword(Keyword::ExperimentalAudit),
	"EXPERIMENTAL_FINGERPRINTS" => PostgresToken::Keyword(Keyword::ExperimentalFingerprints),
	"EXPERIMENTAL_RELOCATE" => PostgresToken::Keyword(Keyword::ExperimentalRelocate),
	"EXPERIMENTAL_REPLICA" => PostgresToken::Keyword(Keyword::ExperimentalReplica),
	"EXPIRATION" => PostgresToken::Keyword(Keyword::Expiration),
	"FAILURE" => PostgresToken::Keyword(Keyword::Failure),
	"FILTER" => PostgresToken::Keyword(Keyword::Filter),
	"FOLLOWING" => PostgresToken::Keyword(Keyword::Following),
	"FORCE" => PostgresToken::Keyword(Keyword::Force),
	"FORCE_INDEX" => PostgresToken::Keyword(Keyword::ForceIndex),
	"FORCE_ZIGZAG" => PostgresToken::Keyword(Keyword::ForceZigzag),
	"FORWARD" => PostgresToken::Keyword(Keyword::Forward),
	"FREEZE" => PostgresToken::Keyword(Keyword::Freeze),
	"FUNCTION" => PostgresToken::Keyword(Keyword::Function),
	"FUNCTIONS" => PostgresToken::Keyword(Keyword::Functions),
	"GENERATED" => PostgresToken::Keyword(Keyword::Generated),
	"GEOMETRYM" => PostgresToken::Keyword(Keyword::Geometrym),
	"GEOMETRYZ" => PostgresToken::Keyword(Keyword::Geometryz),
	"GEOMETRYZM" => PostgresToken::Keyword(Keyword::Geometryzm),
	"GEOMETRYCOLLECTION" => PostgresToken::Keyword(Keyword::Geometrycollection),
	"GEOMETRYCOLLECTIONM" => PostgresToken::Keyword(Keyword::Geometrycollectionm),
	"GEOMETRYCOLLECTIONZ" => PostgresToken::Keyword(Keyword::Geometrycollectionz),
	"GEOMETRYCOLLECTIONZM" => PostgresToken::Keyword(Keyword::Geometrycollectionzm),
	"GLOBAL" => PostgresToken::Keyword(Keyword::Global),
	"GROUPS" => PostgresToken::Keyword(Keyword::Groups),
	"HASH" => PostgresToken::Keyword(Keyword::Hash),
	"HEADER" => PostgresToken::Keyword(Keyword::Header),
	"HIGH" => PostgresToken::Keyword(Keyword::High),
	"HISTOGRAM" => PostgresToken::Keyword(Keyword::Histogram),
	"HOUR" => PostgresToken::Keyword(Keyword::Hour),
	"IDENTITY" => PostgresToken::Keyword(Keyword::Identity),
	"IMMEDIATE" => PostgresToken::Keyword(Keyword::Immediate),
	"INCLUDE" => PostgresToken::Keyword(Keyword::Include),
	"INCLUDING" => PostgresToken::Keyword(Keyword::Including),
	"INCREMENT" => PostgresToken::Keyword(Keyword::Increment),
	"INCREMENTAL_LOCATION" => PostgresToken::Keyword(Keyword::IncrementalLocation),
	"INHERITS" => PostgresToken::Keyword(Keyword::Inherits),
	"INJECT" => PostgresToken::Keyword(Keyword::Inject),
	"INTO_DB" => PostgresToken::Keyword(Keyword::IntoDb),
	"INVERTED" => PostgresToken::Keyword(Keyword::Inverted),
	"ISOLATION" => PostgresToken::Keyword(Keyword::Isolation),
	"JSON" => PostgresToken::Keyword(Keyword::Json),
	"KEY" => PostgresToken::Keyword(Keyword::Key),
	"KMS" => PostgresToken::Keyword(Keyword::Kms),
	"LANGUAGE" => PostgresToken::Keyword(Keyword::Language),
	"LC_COLLATE" => PostgresToken::Keyword(Keyword::LcCollate),
	"LC_CTYPE" => PostgresToken::Keyword(Keyword::LcCtype),
	"LEASE" => PostgresToken::Keyword(Keyword::Lease),
	"LESS" => PostgresToken::Keyword(Keyword::Less),
	"LEVEL" => PostgresToken::Keyword(Keyword::Level),
	"LINESTRING" => PostgresToken::Keyword(Keyword::Linestring),
	"LINESTRINGM" => PostgresToken::Keyword(Keyword::Linestringm),
	"LINESTRINGZ" => PostgresToken::Keyword(Keyword::Linestringz),
	"LINESTRINGZM" => PostgresToken::Keyword(Keyword::Linestringzm),
	"LIST" => PostgresToken::Keyword(Keyword::List),
	"LOCKED" => PostgresToken::Keyword(Keyword::Locked),
	"LOGIN" => PostgresToken::Keyword(Keyword::Login),
	"LOOKUP" => PostgresToken::Keyword(Keyword::Lookup),
	"LOW" => PostgresToken::Keyword(Keyword::Low),
	"MATCH" => PostgresToken::Keyword(Keyword::Match),
	"MAXVALUE" => PostgresToken::Keyword(Keyword::Maxvalue),
	"MERGE" => PostgresToken::Keyword(Keyword::Merge),
	"METHOD" => PostgresToken::Keyword(Keyword::Method),
	"MINUTE" => PostgresToken::Keyword(Keyword::Minute),
	"MINVALUE" => PostgresToken::Keyword(Keyword::Minvalue),
	"MODIFYCLUSTERSETTING" => PostgresToken::Keyword(Keyword::Modifyclustersetting),
	"MULTILINESTRING" => PostgresToken::Keyword(Keyword::Multilinestring),
	"MULTILINESTRINGM" => PostgresToken::Keyword(Keyword::Multilinestringm),
	"MULTILINESTRINGZ" => PostgresToken::Keyword(Keyword::Multilinestringz),
	"MULTILINESTRINGZM" => PostgresToken::Keyword(Keyword::Multilinestringzm),
	"MULTIPOINT" => PostgresToken::Keyword(Keyword::Multipoint),
	"MULTIPOINTM" => PostgresToken::Keyword(Keyword::Multipointm),
	"MULTIPOINTZ" => PostgresToken::Keyword(Keyword::Multipointz),
	"MULTIPOINTZM" => PostgresToken::Keyword(Keyword::Multipointzm),
	"MULTIPOLYGON" => PostgresToken::Keyword(Keyword::Multipolygon),
	"MULTIPOLYGONM" => PostgresToken::Keyword(Keyword::Multipolygonm),
	"MULTIPOLYGONZ" => PostgresToken::Keyword(Keyword::Multipolygonz),
	"MULTIPOLYGONZM" => PostgresToken::Keyword(Keyword::Multipolygonzm),
	"MONTH" => PostgresToken::Keyword(Keyword::Month),
	"NAMES" => PostgresToken::Keyword(Keyword::Names),
	"NAN" => PostgresToken::Keyword(Keyword::Nan),
	"NEVER" => PostgresToken::Keyword(Keyword::Never),
	"NEW_DB_NAME" => PostgresToken::Keyword(Keyword::NewDbName),
	"NEW_KMS" => PostgresToken::Keyword(Keyword::NewKms),
	"NEXT" => PostgresToken::Keyword(Keyword::Next),
	"NORMAL" => PostgresToken::Keyword(Keyword::Normal),
	"NO_INDEX_JOIN" => PostgresToken::Keyword(Keyword::NoIndexJoin),
	"NO_ZIGZAG_JOIN" => PostgresToken::Keyword(Keyword::NoZigzagJoin),
	"NO_FULL_SCAN" => PostgresToken::Keyword(Keyword::NoFullScan),
	"NOCREATEDB" => PostgresToken::Keyword(Keyword::Nocreatedb),
	"NOCREATELOGIN" => PostgresToken::Keyword(Keyword::Nocreatelogin),
	"NOCANCELQUERY" => PostgresToken::Keyword(Keyword::Nocancelquery),
	"NOCREATEROLE" => PostgresToken::Keyword(Keyword::Nocreaterole),
	"NOCONTROLCHANGEFEED" => PostgresToken::Keyword(Keyword::Nocontrolchangefeed),
	"NOCONTROLJOB" => PostgresToken::Keyword(Keyword::Nocontroljob),
	"NOLOGIN" => PostgresToken::Keyword(Keyword::Nologin),
	"NOMODIFYCLUSTERSETTING" => PostgresToken::Keyword(Keyword::Nomodifyclustersetting),
	"NONVOTERS" => PostgresToken::Keyword(Keyword::Nonvoters),
	"NOSQLLOGIN" => PostgresToken::Keyword(Keyword::Nosqllogin),
	"NOVIEWACTIVITY" => PostgresToken::Keyword(Keyword::Noviewactivity),
	"NOVIEWACTIVITYREDACTED" => PostgresToken::Keyword(Keyword::Noviewactivityredacted),
	"NOVIEWCLUSTERSETTING" => PostgresToken::Keyword(Keyword::Noviewclustersetting),
	"NOWAIT" => PostgresToken::Keyword(Keyword::Nowait),
	"NULLS" => PostgresToken::Keyword(Keyword::Nulls),
	"IGNORE_FOREIGN_KEYS" => PostgresToken::Keyword(Keyword::IgnoreForeignKeys),
	"OFF" => PostgresToken::Keyword(Keyword::Off),
	"OIDS" => PostgresToken::Keyword(Keyword::Oids),
	"OLD_KMS" => PostgresToken::Keyword(Keyword::OldKms),
	"OPERATOR" => PostgresToken::Keyword(Keyword::Operator),
	"OPT" => PostgresToken::Keyword(Keyword::Opt),
	"ORDINALITY" => PostgresToken::Keyword(Keyword::Ordinality),
	"OTHERS" => PostgresToken::Keyword(Keyword::Others),
	"OVER" => PostgresToken::Keyword(Keyword::Over),
	"OWNER" => PostgresToken::Keyword(Keyword::Owner),
	"PARENT" => PostgresToken::Keyword(Keyword::Parent),
	"PARTIAL" => PostgresToken::Keyword(Keyword::Partial),
	"PASSWORD" => PostgresToken::Keyword(Keyword::Password),
	"PAUSED" => PostgresToken::Keyword(Keyword::Paused),
	"PHYSICAL" => PostgresToken::Keyword(Keyword::Physical),
	"PLACEMENT" => PostgresToken::Keyword(Keyword::Placement),
	"PLAN" => PostgresToken::Keyword(Keyword::Plan),
	"PLANS" => PostgresToken::Keyword(Keyword::Plans),
	"POINTM" => PostgresToken::Keyword(Keyword::Pointm),
	"POINTZ" => PostgresToken::Keyword(Keyword::Pointz),
	"POINTZM" => PostgresToken::Keyword(Keyword::Pointzm),
	"POLYGONM" => PostgresToken::Keyword(Keyword::Polygonm),
	"POLYGONZ" => PostgresToken::Keyword(Keyword::Polygonz),
	"POLYGONZM" => PostgresToken::Keyword(Keyword::Polygonzm),
	"PRECEDING" => PostgresToken::Keyword(Keyword::Preceding),
	"PRESERVE" => PostgresToken::Keyword(Keyword::Preserve),
	"PRIOR" => PostgresToken::Keyword(Keyword::Prior),
	"PRIORITY" => PostgresToken::Keyword(Keyword::Priority),
	"PUBLIC" => PostgresToken::Keyword(Keyword::Public),
	"PUBLICATION" => PostgresToken::Keyword(Keyword::Publication),
	"QUOTE" => PostgresToken::Keyword(Keyword::Quote),
	"READ" => PostgresToken::Keyword(Keyword::Read),
	"RECURRING" => PostgresToken::Keyword(Keyword::Recurring),
	"RECURSIVE" => PostgresToken::Keyword(Keyword::Recursive),
	"REF" => PostgresToken::Keyword(Keyword::Ref),
	"REGION" => PostgresToken::Keyword(Keyword::Region),
	"REGIONAL" => PostgresToken::Keyword(Keyword::Regional),
	"REINDEX" => PostgresToken::Keyword(Keyword::Reindex),
	"RELOCATE" => PostgresToken::Keyword(Keyword::Relocate),
	"RENAME" => PostgresToken::Keyword(Keyword::Rename),
	"REPEATABLE" => PostgresToken::Keyword(Keyword::Repeatable),
	"REPLACE" => PostgresToken::Keyword(Keyword::Replace),
	"RESTRICTED" => PostgresToken::Keyword(Keyword::Restricted),
	"RETRY" => PostgresToken::Keyword(Keyword::Retry),
	"REVISION_HISTORY" => PostgresToken::Keyword(Keyword::RevisionHistory),
	"ROLE" => PostgresToken::Keyword(Keyword::Role),
	"ROLLUP" => PostgresToken::Keyword(Keyword::Rollup),
	"ROUTINES" => PostgresToken::Keyword(Keyword::Routines),
	"ROWS" => PostgresToken::Keyword(Keyword::Rows),
	"RULE" => PostgresToken::Keyword(Keyword::Rule),
	"RUNNING" => PostgresToken::Keyword(Keyword::Running),
	"SETTINGS" => PostgresToken::Keyword(Keyword::Settings),
	"SCATTER" => PostgresToken::Keyword(Keyword::Scatter),
	"SEARCH" => PostgresToken::Keyword(Keyword::Search),
	"SECOND" => PostgresToken::Keyword(Keyword::Second),
	"SERIALIZABLE" => PostgresToken::Keyword(Keyword::Serializable),
	"SEQUENCE" => PostgresToken::Keyword(Keyword::Sequence),
	"SERVER" => PostgresToken::Keyword(Keyword::Server),
	"SETS" => PostgresToken::Keyword(Keyword::Sets),
	"SHARE" => PostgresToken::Keyword(Keyword::Share),
	"SIMPLE" => PostgresToken::Keyword(Keyword::Simple),
	"SKIP" => PostgresToken::Keyword(Keyword::Skip),
	"SKIP_LOCALITIES_CHECK" => PostgresToken::Keyword(Keyword::SkipLocalitiesCheck),
	"SKIP_MISSING_FOREIGN_KEYS" => PostgresToken::Keyword(Keyword::SkipMissingForeignKeys),
	"SKIP_MISSING_SEQUENCES" => PostgresToken::Keyword(Keyword::SkipMissingSequences),
	"SKIP_MISSING_SEQUENCE_OWNERS" => PostgresToken::Keyword(Keyword::SkipMissingSequenceOwners),
	"SKIP_MISSING_VIEWS" => PostgresToken::Keyword(Keyword::SkipMissingViews),
	"SNAPSHOT" => PostgresToken::Keyword(Keyword::Snapshot),
	"SPLIT" => PostgresToken::Keyword(Keyword::Split),
	"SQL" => PostgresToken::Keyword(Keyword::Sql),
	"SQLLOGIN" => PostgresToken::Keyword(Keyword::Sqllogin),
	"STATEMENTS" => PostgresToken::Keyword(Keyword::Statements),
	"STORAGE" => PostgresToken::Keyword(Keyword::Storage),
	"STORE" => PostgresToken::Keyword(Keyword::Store),
	"STORED" => PostgresToken::Keyword(Keyword::Stored),
	"STORING" => PostgresToken::Keyword(Keyword::Storing),
	"STRICT" => PostgresToken::Keyword(Keyword::Strict),
	"SUBSCRIPTION" => PostgresToken::Keyword(Keyword::Subscription),
	"SURVIVE" => PostgresToken::Keyword(Keyword::Survive),
	"SYNTAX" => PostgresToken::Keyword(Keyword::Syntax),
	"TABLESPACE" => PostgresToken::Keyword(Keyword::Tablespace),
	"TEMP" => PostgresToken::Keyword(Keyword::Temp),
	"TEMPLATE" => PostgresToken::Keyword(Keyword::Template),
	"TEMPORARY" => PostgresToken::Keyword(Keyword::Temporary),
	"TESTING_RELOCATE" => PostgresToken::Keyword(Keyword::TestingRelocate),
	"TEXT" => PostgresToken::Keyword(Keyword::Text),
	"TIES" => PostgresToken::Keyword(Keyword::Ties),
	"TRIGGER" => PostgresToken::Keyword(Keyword::Trigger),
	"TRUSTED" => PostgresToken::Keyword(Keyword::Trusted),
	"THROTTLING" => PostgresToken::Keyword(Keyword::Throttling),
	"UNBOUNDED" => PostgresToken::Keyword(Keyword::Unbounded),
	"UNCOMMITTED" => PostgresToken::Keyword(Keyword::Uncommitted),
	"UNKNOWN" => PostgresToken::Keyword(Keyword::Unknown),
	"UNLOGGED" => PostgresToken::Keyword(Keyword::Unlogged),
	"UNSET" => PostgresToken::Keyword(Keyword::Unset),
	"UNSPLIT" => PostgresToken::Keyword(Keyword::Unsplit),
	"UNTIL" => PostgresToken::Keyword(Keyword::Until),
	"VALID" => PostgresToken::Keyword(Keyword::Valid),
	"VALIDATE" => PostgresToken::Keyword(Keyword::Validate),
	"VALUE" => PostgresToken::Keyword(Keyword::Value),
	"VARYING" => PostgresToken::Keyword(Keyword::Varying),
	"VIEWACTIVITY" => PostgresToken::Keyword(Keyword::Viewactivity),
	"VIEWACTIVITYREDACTED" => PostgresToken::Keyword(Keyword::Viewactivityredacted),
	"VIEWCLUSTERSETTING" => PostgresToken::Keyword(Keyword::Viewclustersetting),
	"VISIBLE" => PostgresToken::Keyword(Keyword::Visible),
	"VOTERS" => PostgresToken::Keyword(Keyword::Voters),
	"WITHIN" => PostgresToken::Keyword(Keyword::Within),
	"WRITE" => PostgresToken::Keyword(Keyword::Write),
	"YEAR" => PostgresToken::Keyword(Keyword::Year),
	"ANNOTATE_TYPE" => PostgresToken::Keyword(Keyword::AnnotateType),
	"BETWEEN" => PostgresToken::Keyword(Keyword::Between),
	"BIGINT" => PostgresToken::Keyword(Keyword::Bigint),
	"BIT" => PostgresToken::Keyword(Keyword::Bit),
	"BOOLEAN" => PostgresToken::Keyword(Keyword::Boolean),
	"BOX2D" => PostgresToken::Keyword(Keyword::Box2d),
	"CHAR" => PostgresToken::Keyword(Keyword::Char),
	"CHARACTER" => PostgresToken::Keyword(Keyword::Character),
	"COALESCE" => PostgresToken::Keyword(Keyword::Coalesce),
	"DEC" => PostgresToken::Keyword(Keyword::Dec),
	"DECIMAL" => PostgresToken::Keyword(Keyword::Decimal),
	"EXTRACT" => PostgresToken::Keyword(Keyword::Extract),
	"EXTRACT_DURATION" => PostgresToken::Keyword(Keyword::ExtractDuration),
	"FLOAT" => PostgresToken::Keyword(Keyword::Float),
	"GEOGRAPHY" => PostgresToken::Keyword(Keyword::Geography),
	"GEOMETRY" => PostgresToken::Keyword(Keyword::Geometry),
	"GREATEST" => PostgresToken::Keyword(Keyword::Greatest),
	"GROUPING" => PostgresToken::Keyword(Keyword::Grouping),
	"IFERROR" => PostgresToken::Keyword(Keyword::Iferror),
	"IFNULL" => PostgresToken::Keyword(Keyword::Ifnull),
	"INT" => PostgresToken::Keyword(Keyword::Int),
	"INTEGER" => PostgresToken::Keyword(Keyword::Integer),
	"INTERVAL" => PostgresToken::Keyword(Keyword::Interval),
	"ISERROR" => PostgresToken::Keyword(Keyword::Iserror),
	"LEAST" => PostgresToken::Keyword(Keyword::Least),
	"NULLIF" => PostgresToken::Keyword(Keyword::Nullif),
	"NUMERIC" => PostgresToken::Keyword(Keyword::Numeric),
	"OUT" => PostgresToken::Keyword(Keyword::Out),
	"OVERLAY" => PostgresToken::Keyword(Keyword::Overlay),
	"POINT" => PostgresToken::Keyword(Keyword::Point),
	"POLYGON" => PostgresToken::Keyword(Keyword::Polygon),
	"POSITION" => PostgresToken::Keyword(Keyword::Position),
	"PRECISION" => PostgresToken::Keyword(Keyword::Precision),
	"REAL" => PostgresToken::Keyword(Keyword::Real),
	"SMALLINT" => PostgresToken::Keyword(Keyword::Smallint),
	"STRING" => PostgresToken::Keyword(Keyword::String),
	"SUBSTRING" => PostgresToken::Keyword(Keyword::Substring),
	"TIME" => PostgresToken::Keyword(Keyword::Time),
	"TIMETZ" => PostgresToken::Keyword(Keyword::Timetz),
	"TIMESTAMP" => PostgresToken::Keyword(Keyword::Timestamp),
	"TIMESTAMPTZ" => PostgresToken::Keyword(Keyword::Timestamptz),
	"TREAT" => PostgresToken::Keyword(Keyword::Treat),
	"TRIM" => PostgresToken::Keyword(Keyword::Trim),
	"VARBIT" => PostgresToken::Keyword(Keyword::Varbit),
	"VARCHAR" => PostgresToken::Keyword(Keyword::Varchar),
	"VIRTUAL" => PostgresToken::Keyword(Keyword::Virtual),
	"WORK" => PostgresToken::Keyword(Keyword::Work),
	"SELECT" => PostgresToken::Keyword(Keyword::Select),
	"USER" => PostgresToken::Keyword(Keyword::User),
	"TRUE" => PostgresToken::Keyword(Keyword::True),
	"FALSE" => PostgresToken::Keyword(Keyword::False),
	"ARRAY" => PostgresToken::Keyword(Keyword::Array),
	"TYPEANNOTATE" => PostgresToken::Keyword(Keyword::Typeannotate),
	"COLLATE" => PostgresToken::Keyword(Keyword::Collate),
	"JSON_SOME_EXISTS" => PostgresToken::Keyword(Keyword::JsonSomeExists),
	"JSON_ALL_EXISTS" => PostgresToken::Keyword(Keyword::JsonAllExists),
	"CONTAINS" => PostgresToken::Keyword(Keyword::Contains),
	"CONTAINED_BY" => PostgresToken::Keyword(Keyword::ContainedBy),
	"FETCHVAL" => PostgresToken::Keyword(Keyword::Fetchval),
	"FETCHTEXT" => PostgresToken::Keyword(Keyword::Fetchtext),
	"FETCHVAL_PATH" => PostgresToken::Keyword(Keyword::FetchvalPath),
	"FETCHTEXT_PATH" => PostgresToken::Keyword(Keyword::FetchtextPath),
	"REMOVE_PATH" => PostgresToken::Keyword(Keyword::RemovePath),
	"AND" => PostgresToken::Keyword(Keyword::And),
	"OR" => PostgresToken::Keyword(Keyword::Or),
	"LIKE" => PostgresToken::Keyword(Keyword::Like),
	"ILIKE" => PostgresToken::Keyword(Keyword::Ilike),
	"SIMILAR" => PostgresToken::Keyword(Keyword::Similar),
	"ISNULL" => PostgresToken::Keyword(Keyword::Isnull),
	"NOTNULL" => PostgresToken::Keyword(Keyword::Notnull),
	"DISTINCT" => PostgresToken::Keyword(Keyword::Distinct),
	"SYMMETRIC" => PostgresToken::Keyword(Keyword::Symmetric),
	"AUTHORIZATION" => PostgresToken::Keyword(Keyword::Authorization),
	"ORDER" => PostgresToken::Keyword(Keyword::Order),
	"LIMIT" => PostgresToken::Keyword(Keyword::Limit),
	"ONLY" => PostgresToken::Keyword(Keyword::Only),
	"ASYMMETRIC" => PostgresToken::Keyword(Keyword::Asymmetric),
	"ANY" => PostgresToken::Keyword(Keyword::Any),
	"SOME" => PostgresToken::Keyword(Keyword::Some),
	"UNIQUE" => PostgresToken::Keyword(Keyword::Unique),
	"USING" => PostgresToken::Keyword(Keyword::Using),
	"FAMILY" => PostgresToken::Keyword(Keyword::Family),
	"UNION" => PostgresToken::Keyword(Keyword::Union),
	"INTERSECT" => PostgresToken::Keyword(Keyword::Intersect),
	"EXCEPT" => PostgresToken::Keyword(Keyword::Except),
	"OFFSET" => PostgresToken::Keyword(Keyword::Offset),
	"LATERAL" => PostgresToken::Keyword(Keyword::Lateral),
	"ASC" => PostgresToken::Keyword(Keyword::Asc),
	"BOTH" => PostgresToken::Keyword(Keyword::Both),
	"CASE" => PostgresToken::Keyword(Keyword::Case),
	"CAST" => PostgresToken::Keyword(Keyword::Cast),
	"CHECK" => PostgresToken::Keyword(Keyword::Check),
	"CURRENT_CATALOG" => PostgresToken::Keyword(Keyword::CurrentCatalog),
	"CURRENT_DATE" => PostgresToken::Keyword(Keyword::CurrentDate),
	"CURRENT_ROLE" => PostgresToken::Keyword(Keyword::CurrentRole),
	"CURRENT_SCHEMA" => PostgresToken::Keyword(Keyword::CurrentSchema),
	"CURRENT_TIME" => PostgresToken::Keyword(Keyword::CurrentTime),
	"CURRENT_TIMESTAMP" => PostgresToken::Keyword(Keyword::CurrentTimestamp),
	"DEFERRABLE" => PostgresToken::Keyword(Keyword::Deferrable),
	"DESC" => PostgresToken::Keyword(Keyword::Desc),
	"ELSE" => PostgresToken::Keyword(Keyword::Else),
	"FOREIGN" => PostgresToken::Keyword(Keyword::Foreign),
	"GROUP" => PostgresToken::Keyword(Keyword::Group),
	"HAVING" => PostgresToken::Keyword(Keyword::Having),
	"INITIALLY" => PostgresToken::Keyword(Keyword::Initially),
	"LEADING" => PostgresToken::Keyword(Keyword::Leading),
	"LOCALTIME" => PostgresToken::Keyword(Keyword::Localtime),
	"LOCALTIMESTAMP" => PostgresToken::Keyword(Keyword::Localtimestamp),
	"PLACING" => PostgresToken::Keyword(Keyword::Placing),
	"PRIMARY" => PostgresToken::Keyword(Keyword::Primary),
	"REFERENCES" => PostgresToken::Keyword(Keyword::References),
	"THEN" => PostgresToken::Keyword(Keyword::Then),
	"TRAILING" => PostgresToken::Keyword(Keyword::Trailing),
	"VARIADIC" => PostgresToken::Keyword(Keyword::Variadic),
	"WINDOW" => PostgresToken::Keyword(Keyword::Window),
	"COLLATION" => PostgresToken::Keyword(Keyword::Collation),
	"CROSS" => PostgresToken::Keyword(Keyword::Cross),
	"JOIN" => PostgresToken::Keyword(Keyword::Join),
	"NATURAL" => PostgresToken::Keyword(Keyword::Natural),
	"INNER" => PostgresToken::Keyword(Keyword::Inner),
	"LEFT" => PostgresToken::Keyword(Keyword::Left),
	"NONE" => PostgresToken::Keyword(Keyword::None),
	"OUTER" => PostgresToken::Keyword(Keyword::Outer),
	"OVERLAPS" => PostgresToken::Keyword(Keyword::Overlaps),
	"RIGHT" => PostgresToken::Keyword(Keyword::Right),
	"DATE" => PostgresToken::Keyword(Keyword::Date),
	"GENERATED_ALWAYS" => PostgresToken::Keyword(Keyword::GeneratedAlways),
	"GENERATED_BY_DEFAULT" => PostgresToken::Keyword(Keyword::GeneratedByDefault)
};


// And today's award for strangest code goes to...
impl PartialEq for PostgresToken {
    fn eq(&self, other:&Self) -> bool {
        match self {
            PostgresToken::UnknownToken(u1) => match other {
                PostgresToken::UnknownToken(u2) => u1 == u2,
                _ => false
            },
            PostgresToken::Identifier(i1) => match other {
                PostgresToken::Identifier(i2) => i1 == i2,
                _ => false
            },
            PostgresToken::Sconst(_) => match other {
                PostgresToken::Sconst(_) => true,
                _ => false
            },
            PostgresToken::Bconst(_) => match other {
                PostgresToken::Bconst(_) => true,
                _ => false
            },
            PostgresToken::Bitconst(_) => match other {
                PostgresToken::Bitconst(_) => true,
                _ => false
            },
            PostgresToken::Iconst(_) => match other {
                PostgresToken::Iconst(_) => true,
                _ => false
            },
            PostgresToken::Fconst(_) => match other {
                PostgresToken::Fconst(_) => true,
                _ => false
            },
            PostgresToken::Placeholder(p1) => match other {
                PostgresToken::Placeholder(p2) => p1 == p2,
                _ => false
            },
            PostgresToken::Keyword(k1) => match other {
                PostgresToken::Keyword(k2) => k1 == k2,
                _ => false
            },
            PostgresToken::LineComment(l1) => match other {
                PostgresToken::LineComment(l2) => l1 == l2,
                _ => false
            },
            PostgresToken::BlockComment(b1) => match other {
                PostgresToken::BlockComment(b2) => b1 == b2,
                _ => false
            },
            PostgresToken::Symbol(c1) => match other {
                PostgresToken::Symbol(c2) => c1 == c2,
                _ => false
            },
            PostgresToken::Whitespace(c1) => match other {
                PostgresToken::Whitespace(c2) => c1 == c2,
                _ => false
            },
        }
    }
}


impl Eq for PostgresToken {}


impl SqlToken for PostgresToken {
    fn deep_eq(&self, other:&Self) -> bool {
        (self == other) && match self {
            PostgresToken::Sconst(s1) |
            PostgresToken::Bconst(s1) |
            PostgresToken::Bitconst(s1) |
            PostgresToken::Iconst(s1) |
            PostgresToken::Fconst(s1) => match other {
                PostgresToken::Sconst(s2) |
                PostgresToken::Bconst(s2) |
                PostgresToken::Bitconst(s2) |
                PostgresToken::Iconst(s2) |
                PostgresToken::Fconst(s2) => {
                    s1 == s2
                },
                _ => false
            },
            _ => true
        }
    }

    fn is_param_token(&self) -> bool {
        match self {
            PostgresToken::Sconst(_) |
            PostgresToken::Bconst(_) |
            PostgresToken::Bitconst(_) |
            PostgresToken::Iconst(_) |
            PostgresToken::Fconst(_) => true,
            _ => false
        }
    }

    fn scan_from(query:&str) -> Vec<Self> {
		let mut tokens = vec!();
		let mut chars:Vec<char> = vec!();
		let mut iter = query.chars().peekable();

		while let Some(c) = iter.next() {
			tokens.push(match (c, iter.peek()) {
				('-',Some('-')) => {
					iter.next(); // consume '-'
					let mut comment = String::new();
					while let Some(c) = iter.next() {
						comment.push(c); // TODO: there's got to be some better way to do this?
					}
					PostgresToken::LineComment(comment)
				},
				('/',Some('*')) => {
					iter.next(); // consume '*'
					match_block_comment(&mut iter)
				}
				('\'',_) => match_apostraphe(&mut iter),
				('"',_) => match_identifier_quot(&mut iter),
				('b',Some('\'')) => {
					iter.next(); // consume '\''
					match_bconst(&mut iter)
				},
				('B',Some('\'')) => {
					iter.next(); // consume '\''
					match_bitconst(&mut iter)
				},
				('x',Some('\'')) => {
					iter.next(); // consume '\''
					match_iconst_x(&mut iter)
				},
				('.',Some('0'..='9')) => match_fconst_period(&mut iter, vec!('.')),
				('$',Some(p)) => match_dollar_opening(&mut iter),
				('$',None) => PostgresToken::UnknownToken(c),
				('_',_) => match_kw_id(&mut iter, vec!('_')),
				(('/' | '-' | '^' | ';' | '(' | ')' | '@' | ',' | '=' | 
				 '*' | '+' | '~' | '%' | '#' | '&' | '|' | '<' | '>' |
				 '?' | '[' | ']' | '{' | '}' | ':' | '.'),_) => PostgresToken::Symbol(c),
				((' ' | '\t' | '\r' | '\n'), _) => PostgresToken::Whitespace(c),
				('0',Some('x')) => { 
					iter.next();
					match_iconst_0x(&mut iter)
				},
				('0'..='9',_) => match_const_digit(&mut iter, vec!(c)),
				(c,_) => { 
					if c.is_alphabetic() {
						match_kw_id(&mut iter, vec!(c))
						// "SQL identifiers and key words must begin with a letter (a-z, but also letters with diacritical marks and non-Latin letters)
						// or an underscore". Rip.
					} else {
						PostgresToken::UnknownToken(c) // Not alphanumeric, and not any of the special chars we listed above: must be a Weasley
					}
				}
			});
		}

        tokens
    }

	// Currently covers:
	// - Injected semicolons
	// - Injected comments
    fn is_malicious_query(pattern: &Vec<Self>) -> bool {
		let mut iter = pattern.iter();
		while let Some(token) = iter.next() {
			match token {
				PostgresToken::Symbol(';') | PostgresToken::LineComment(_) => return true,
				PostgresToken::Identifier(i) => { 
					// Block metadata tables here
					// Block file/socket/exec functions here?
				},
				PostgresToken::Keyword(Keyword::Union) => {
					// TODO: is this already covered by blocking metadata tables?
				},
				PostgresToken::Keyword(Keyword::Or) => if is_tautology(iter.clone()) { return true },
				/*
				PostgresToken::Keyword(Keyword::And) => {
					// Call function here that checks for negative tautology immediately following 'AND'?
				},
				*/
				_ => ()
			}
		};

		match pattern.last() {
			Some(PostgresToken::BlockComment(_)) => true, // Or should we just reject block comments anywhere?
			_ => false
		}
	}
}

fn is_tautology(mut iter: std::slice::Iter<PostgresToken>) -> bool {
	// Watch out for precedence of OR/AND operators (among other operators and operations) here

	// We *could* make a fully-fledged parser that checks whether a 
	// given mathematical operation will always be true here... (halting probs)
	// OR we could just see if any tables/column values are used. It is unlikely 
	// (though far from impossible) that a programmer would use a hardcoded tautology 
	// such as `... WHERE <user_input_value> = 42`, and it becomes more unlikely 
	// when we only check for tautologies immediately following 'OR' and its variants.

	for token in iter {
		match token {
			//PostgresToken::Keyword(Keyword::And) | PostgresToken::Keyword(Keyword::)
			PostgresToken::Identifier(_) | PostgresToken::Keyword(_) => {
				// a_expr in CockroachDB
			}
			_ => {}
		};
	}

	false
}


fn read_until(iter: &mut std::iter::Peekable<std::str::Chars>, c:char) -> String {
	let mut chars = vec!();
	
	while let Some(n) = iter.next() {
		match n {
			c => return chars.into_iter().collect::<String>(),
			_ => { chars.push(n); }
		};
	};

	chars.into_iter().collect::<String>()
}

fn match_block_comment(iter: &mut std::iter::Peekable<std::str::Chars>) -> PostgresToken {
	let mut chars = vec!('/','*');
	let mut nested_depth = 1;

	while let Some(c) = iter.next() {
		match (c,iter.peek()) {
			('/',Some('*')) => {
				nested_depth += 1; // Another nested '/*'
				iter.next(); // Consume '*'
				chars.push('/');
				chars.push('*');
			}
			('*',Some('/')) => {
				if nested_depth > 1 {
					nested_depth -= 1;
					iter.next(); // Consume '/'
					chars.push('*');
					chars.push('/');
				} else {
					iter.next(); // Consume '/'
					return PostgresToken::BlockComment(chars.into_iter().collect::<String>())
				}
			}
			_ => { chars.push(c); }
		};
	};
	
	// Block comment did not have proper closing 
	PostgresToken::BlockComment(chars.into_iter().collect::<String>())
}

fn match_apostraphe(iter: &mut std::iter::Peekable<std::str::Chars>) -> PostgresToken {
	let mut chars = vec!();
	
	while let (Some(c), p) = (iter.next(), iter.peek()) {
		match (c, p) {
			('\'' | '\\', Some('\'')) => {
				chars.push(c);
				chars.push('\'');
				iter.next();
			},
			('\'', _) => {
				return PostgresToken::Sconst(chars.into_iter().collect::<String>());
			},
			_ => { chars.push(c); }
		};
	};

	PostgresToken::Sconst(chars.into_iter().collect::<String>())
}

fn match_bconst(iter: &mut std::iter::Peekable<std::str::Chars>) -> PostgresToken {
	PostgresToken::Bconst(read_until(iter, '\''))
}

fn match_bitconst(iter: &mut std::iter::Peekable<std::str::Chars>) -> PostgresToken {
	PostgresToken::Bitconst(read_until(iter, '\''))
}

fn match_identifier_quot(iter: &mut std::iter::Peekable<std::str::Chars>) -> PostgresToken {
	let mut chars = vec!();
	
	while let (Some(c), p) = (iter.next(), iter.peek()) {
		match (c, p) {
			('"', Some('"')) => { // TODO: does '\\"' count here as well?
				chars.push(c);
				chars.push('"');
				iter.next();
			},
			('"', _) => {
				return PostgresToken::Identifier(chars.into_iter().collect::<String>());
			},
			_ => { chars.push(c); }
		};
	};

	PostgresToken::Sconst(chars.into_iter().collect::<String>())
}

fn match_kw_id(iter: &mut std::iter::Peekable<std::str::Chars>, mut chars: Vec<char>) -> PostgresToken {
	while let Some(p) = iter.peek() {
		if !p.is_alphabetic() && !p.is_ascii_digit() && *p != '_' && *p != '$' {
			break
		}
		chars.push(p.to_ascii_uppercase());
		iter.next();
	};
	
	let identifier = chars.into_iter().collect::<String>();
	match KEYWORDS.get(&identifier) {
		Some(token) => token.clone(),
		None => PostgresToken::Identifier(identifier)
	}
}

fn match_iconst(iter: &mut std::iter::Peekable<std::str::Chars>, mut chars: Vec<char>) -> PostgresToken {
	while let Some(p @ '0'..='9') = iter.peek() {
		chars.push(p.clone());
		iter.next();
	};

	PostgresToken::Iconst(chars.into_iter().collect::<String>())
}

fn match_iconst_x(iter: &mut std::iter::Peekable<std::str::Chars>) -> PostgresToken {
	PostgresToken::Iconst(read_until(iter, '\'')) // iconst x isn't supposed to escape \' or ''
}

fn match_iconst_0x(iter: &mut std::iter::Peekable<std::str::Chars>) -> PostgresToken {
	let mut chars = vec!();
	
	while let Some(n @ ('0'..='9' | 'a'..='f' | 'A'..='F')) = iter.peek() {
		chars.push(n.clone());
		iter.next();
	};

	PostgresToken::Iconst(chars.into_iter().collect::<String>())
}


fn match_fconst_period(iter: &mut std::iter::Peekable<std::str::Chars>, mut chars: Vec<char>) -> PostgresToken {
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
						return match_fconst_e(iter, chars)
					},
					Some('0'..='9') => { return match_fconst_e(iter, chars) },
					Some(_) | None => { break }
				};
			},
			_ => { break }
		};
	};

	PostgresToken::Fconst(chars.into_iter().collect::<String>())
}

fn match_fconst_e(iter: &mut std::iter::Peekable<std::str::Chars>, mut chars: Vec<char>) -> PostgresToken {
	while let Some(p @ '0'..='9') = iter.peek() {
		chars.push(p.clone());
		iter.next();
	};

	PostgresToken::Fconst(chars.into_iter().collect::<String>())
}

fn match_placeholder(iter: &mut std::iter::Peekable<std::str::Chars>) -> PostgresToken {
	let mut chars: Vec<char> = vec!();

	while let Some(p @ ('0'..='9')) = iter.peek() {
		chars.push(p.clone());
		iter.next();
	};

	PostgresToken::Placeholder(chars.into_iter().collect::<String>())
}

fn match_dollar_opening(iter: &mut std::iter::Peekable<std::str::Chars>) -> PostgresToken {
	let mut ident = vec!();
	while let Some(p @ ('a'..='z' | 'A'..='Z' | '0'..='9' | '_')) = iter.peek() {
		ident.push(p.clone());
		iter.next();
	};

	match iter.peek() {
		Some('$') => {
			iter.next();
			match_dollar_sconst(iter, ident.into_iter().collect::<String>())
		},
		_ => PostgresToken::Placeholder(ident.into_iter().collect::<String>()) // TODO: this is an invalid placeholder
	}
}

fn match_dollar_sconst(iter: &mut std::iter::Peekable<std::str::Chars>, mut identifier: String) -> PostgresToken {
	let mut chars: Vec<char> = vec!();
	let mut id_index = None;

	identifier.push('$');

	while let Some(p @ ('a'..='z' | 'A'..='Z' | '0'..='9' | '_' | '$')) = iter.peek() {
		match id_index {
			Some(i) => match chars.get(i) {
				Some(c)=> id_index = if p == c { Some(i + 1) } else { None },
				None => return PostgresToken::Sconst(chars[..chars.len()-i].iter().collect::<String>())
			},
			None => id_index = if *p == '$' { Some(0) } else { None } 
		};

		chars.push(p.clone());
		iter.next();
	};

	PostgresToken::Sconst(chars.into_iter().collect::<String>())
}



fn match_const_digit(iter: &mut std::iter::Peekable<std::str::Chars>, mut chars: Vec<char>) -> PostgresToken {
	while let Some(p @ '0'..='9') = iter.peek() {
		chars.push(p.clone());
		iter.next();
	};

	return match iter.peek() {
		Some('.') => {
			chars.push('.');
			match_fconst_period(iter, chars)
		},
		Some(_) | None => PostgresToken::Iconst(chars.into_iter().collect::<String>())
	}
}