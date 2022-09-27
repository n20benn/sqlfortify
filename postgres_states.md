# PostgreSQL Protocol States 

*By Nathaniel Bennett*


F is the frontend (i.e. the client)
B is the backend (i.e. the SQL server)
P is the proxy (i.e. SQLFortify)

B: <MsgType> -> F and F: <MsgType> -> B both indicate transparent proxying from client to server.

F: <MsgType> -> P indicates that the message should be intercepted by our proxy and MUST NOT be forwarded to the backend

P: <MsgType> -> F indicates that a message should be injected by our proxy into the message stream to the frontend

Side note: We might do well with injecting NegotiateProtocolVersion into any startup with a major version of 3 and minor version we don't yet support


Precedence of conditions (from first to last):
- The specific Message Type listed in the given state
- The specific Message Type listed in the 'ALL' state
- The wildcard Message Type listed in the given state
- The wildcard Message Type listed in the 'ALL' state

So, behaviors in ALL are overridden by behaviors in a given state, and wildcards are overridden by specific message behaviors.

### ALL (Default Behavior)

B: NoticeResponse -> F; nochange
B: ParameterStatus -> F; nochange
B: NotificationResponse -> F; nochange
B: * -> F; PermError

F: Terminate -> B; PermError
F: * -> B; PermError


### ClientStartup

F: StartupMessage -> B; StartupReceived
F: CancelRequest -> B; PermError
F: SSLRequest ONCE -> B; SSLReceived
F: GSSENCRequest ONCE -> B; GSSENCReceived

### StartupReceived

B: ErrorResponse -> F; PermError
B: AuthenticationOk -> F; ServerSetup
B: AuthenticationKerberosV5 -> P; InjectPermErrorClient
B: AuthenticationCleartextPassword -> F; AuthPassword
B: AuthenticationMD5Password -> F; AuthPassword
B: AuthenticationSCMCredential -> P; InjectPermErrorClient 
B: AuthenticationGSS -> F; AuthGSS
B: AuthenticationSSPI -> F; AuthGSS
B: AuthenticationSASL -> F; AuthSASL
B: NegotiateProtocolVersion ONCE -> F; StartupReceived

### SSLReceived
B: SSLResponseS -> F; SSLEncrypt
B: SSLResponseN -> F; ClientStartup

### GSSENCReceived
B: GSSENCResponseG -> F; GSSEncrypt
B: GSSENCResponseN -> F; ClientStartup

### SSLEncrypt
F: <full_ssl_handshake> -> B; ClientStartup

### GSSEncrypt
F: <full_gssapi_handshake> -> B; ClientStartup

### AuthPassword

F: AuthDataResponse -> B; FinalAuthReceived

### AuthGSS

F: AuthDataResponse -> B; AuthGSSReceived

### AuthGSSReceived

B: ErrorResponse -> F; PermError
B: AuthenticationOk -> F; ServerSetup
B: AuthenticationGSSContinue -> F; AuthGSSContinued

### AuthGSSContinued

F: AuthDataResponse -> B; AuthGSSReceived

### AuthSASL

F: AuthDataResponse -> B; AuthSASLReceived

### AuthSASLReceived

B: ErrorResponse -> F; PermError
B: AuthenticationOk -> F; ServerSetup
B: AuthenticationSASLContinue -> F; AuthSASLContinued
B: AuthenticationSASLFinal -> F; FinalAuthReceived

### AuthSASLContinued

F: AuthDataResponse -> B; AuthSASLReceived

### FinalAuthReceived

B: ErrorResponse -> F; PermError
B: AuthenticationOk -> F; ServerSetup

### PermError

**Proxy closes both connections**

### InjectPermErrorClient

P: ErrorResponse -> F; PermError

### ServerSetup

B: ErrorResponse -> F; PermError
B: NegotiateProtocolVersion ONCE -> F; ServerSetup
B: BackendKeyData -> F; ServerSetup
B: ParameterStatus -> F; ServerSetup
B: NoticeResponse -> F; ServerSetup
B: ReadyForQuery -> F; ReadyForCommand

// When an error is detected while processing any extended-query message, the backend issues ErrorResponse, then reads and discards messages until a Sync is reached, then issues ReadyForQuery and returns to normal message processing. (But note that no skipping occurs if an error is detected while processing Sync — this ensures that there is one and only one ReadyForQuery sent for each Sync.)

### ReadyForCommand

F: Query -> B; QueryReceived
F: Parse -> B; ParseReceived
F: Bind -> B; BindReceived
F: Execute -> B; ExecuteReceived
F: Sync -> B; AwaitingReady 
F: Describe -> B; DescribeReceived
F: Close -> B; CloseReceived
F: Flush -> B; ExtendedQuery
F: FunctionCall -> B; FunctionCallReceived
F: CopyData -> B; ReadyForCommand
F: CopyDone -> B; ReadyForCommand
F: CopyFail -> B; ReadyForCommand

### QueryReceived

B: CommandComplete -> F; QueryReceived
B: CopyInResponse -> F; CopyIn
B: CopyOutResponse -> F; CopyOut
B: CopyBothResponse -> F; CopyBoth
B: RowDescription -> F; QueryReceived
B: DataRow -> F; QueryReceived
B: EmptyQueryResponse -> F; QueryReceived
B: ErrorResponse -> F; QueryReceived
B: NoticeResponse -> F; QueryReceived
B: ReadyForQuery -> F; ReadyForCommand
F: CopyData -> B; QueryReceived
F: CopyDone -> B; QueryReceived
F: CopyFail -> B; QueryReceived

### ParseReceived

B: ParseComplete -> F; ExtendedQuery
B: ErrorResponse -> F; AwaitingSync

### ExtendedQuery

F: Parse -> B; ParseReceived
F: Bind -> B; BindReceived
F: Execute -> B; ExecuteReceived
F: Sync -> B; AwaitingReady
F: Describe -> B; DescribeReceived
F: Close -> B; CloseReceived
F: Flush -> B; ExtendedQuery
B: ErrorResponse -> F; AwaitingSync

### BindReceived

B: BindComplete -> F; ExtendedQuery
B: ErrorResponse -> F; AwaitingSync

### ExecuteReceived

B: CommandComplete -> F; ExtendedQuery
B: CopyInResponse -> F; ExecuteCopyIn
B: CopyOutResponse -> F; ExecuteCopyOut
B: DataRow -> F; ExecuteReceived
B: EmptyQueryResponse -> F; ExtendedQuery
B: NoticeResponse -> F; ExecuteReceived
B: PortalSuspended -> F; ExtendedQuery
B: ErrorResponse -> F; AwaitingSync

### AwaitingSync

F: Sync -> B; AwaitingReady
F: * -> B; AwaitingSync

### AwaitingReady

B: ReadyForQuery -> F; ReadyForCommand

### DescribeReceived

B: RowDescription -> F; ExtendedQuery
B: ParameterDescription -> F; ExtendedQuery
B: NoData -> F; ExtendedQuery
B: ErrorResponse -> F; AwaitingSync

### CloseReceived

B: CloseComplete -> F; ExtendedQuery
B: ErrorResponse -> F; AwaitingSync

### FunctionCallReceived

B: ErrorResponse -> F; FunctionCallReceived
B: FunctionCallResponse -> F; FunctionCallReceived
B: NoticeResponse -> F; FunctionCallReceived
B: ReadyForQuery -> F; ReadyForCommand

### CopyIn

F: CopyData -> B; CopyIn
F: CopyDone -> B; QueryReceived
F: CopyFail -> B; QueryReceived
F: Flush -> B; CopyIn
F: Sync -> B; CopyIn
F: * -> B; QueryReceived

### CopyOut

B: CopyData -> F; CopyOut
B: CopyDone -> F; QueryReceived
B: ErrorResponse -> F; QueryReceived

### ExecuteCopyIn

F: CopyData -> B; ExecuteCopyIn
F: CopyDone -> B; ExecuteReceived
F: CopyFail -> B; AwaitingSync
F: Flush -> B; ExecuteCopyIn
F: Sync -> B; ExecuteCopyIn
F: * -> B; AwaitingSync

### ExecuteCopyOut

B: CopyData -> F; ExecuteCopyOut
B: CopyDone -> F; ExecuteReceived
B: ErrorResponse -> F; ExecuteReceived // TODO: wording is ambiguous, should this be ExtendedQuery?

### CopyBoth
F: CopyData -> B; CopyBoth
B: CopyData -> F; CopyBoth
F: CopyDone -> B; CopyOut
B: CopyDone -> F; CopyIn
B: ErrorMessage -> F; AwaitingSync
F: Flush -> B; CopyBoth
F: Sync -> B; CopyBoth
F: * -> B; AwaitingSync



From the PostgreSQL Documentation: When pipelining requests with extended queries, completion must be determined by counting ReadyForQuery messages and waiting for that to reach the number of Syncs sent.

This is a pretty surefire rule for 