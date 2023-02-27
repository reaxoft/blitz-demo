-- IB-2520: add tasks schema

-- TASK PARTITION TABLE
CREATE TABLE TSK_PRT (
	QUE    	  varchar(255) NOT NULL,	-- QUEUE NAME
	RUN_AFT	  bigint NOT NULL,		-- PARTITION TIME - UNIX TIME AFTER WHICH PARTITION MAY BE RUNNING
	LCK_ON    bigint NOT NULL,		-- UNIX TIME WHEN PARTITION IS LOCKED
	CONSTRAINT TSK_PRT_ID_PK PRIMARY key (QUE,RUN_AFT)
);

-- TASK TABLE
CREATE TABLE TSK (
    ID        varchar(255) CONSTRAINT TSK_ID_PK PRIMARY key,    -- TASK ID
	NAM    	  varchar(255) NOT NULL,			-- TASK NAME
	TYP	  varchar(255) NOT NULL,			-- TASK TYP
	BDY 	  text NOT NULL,				-- TASK BODY
	ATM       integer not NULL,				-- TASK PROCESSING ATTEMPT COUNT
	CRT_ON    bigint NOT NULL,				-- TASK CREATION TIME IN MILLISECONDS
	UPD_ON    bigint NOT NULL,				-- TASK UPDATE TIME IN MILLISECONDS
	QUE	  varchar(255) NOT NULL,			-- QUEUE NAME
	RUN_AFT	  bigint NOT NULL,				-- TASK PARTITION TIME
	LCK_ON    bigint NOT NULL,				-- UNIX TIME WHEN TASK IS LOCKED
	LST_ERR	  varchar(255)					-- LAST PROCESSING ERROR
);
