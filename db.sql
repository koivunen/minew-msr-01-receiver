
CREATE TABLE minew (
	measured timestamptz(0) DEFAULT now() NOT NULL,
	deviceid int2 DEFAULT '-123'::integer NOT NULL,
	total_enters int4 DEFAULT '-123'::integer NOT NULL,
	total_exits int4 DEFAULT '-123'::integer NOT NULL,
	CONSTRAINT minew_unique UNIQUE (measured, deviceid)
);

-- TODO: timescale?