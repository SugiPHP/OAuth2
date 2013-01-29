CREATE TABLE oauth_clients (
	client_id 		VARCHAR(32) NOT NULL,
	client_type		VARCHAR(20) NOT NULL,
	client_secret 	VARCHAR(60) NULL,
	redirect_uri	VARCHAR(255) NULL,
	PRIMARY KEY (client_id)
);

CREATE TABLE oauth_codes (
	code 			VARCHAR(128) NOT NULL,
	client_id 		VARCHAR(32) NOT NULL,
	user_id 		INTEGER NOT NULL,
	time_issued 	TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
	expires 		INTEGER NOT NULL,
	scope 			VARCHAR(255) NULL,
	redirect_uri 	VARCHAR(255) NOT NULL,
	PRIMARY KEY (code)
);

CREATE TABLE oauth_tokens (
	token 			VARCHAR(128) NOT NULL,
	client_id 		VARCHAR(32) NOT NULL,
	user_id 		INTEGER NOT NULL,
	time_issued 	TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
	expires 		INTEGER NOT NULL,
	scope 			VARCHAR(255) NULL,
	revoked			INTEGER NOT NULL DEFAULT 0,
	code 			VARCHAR(128) NULL,
	PRIMARY KEY (token)
);
/*
CREATE TABLE oauth_refresh (
	token 			VARCHAR(40) NOT NULL,
	client_id 		VARCHAR(40) NOT NULL,
	user_id 		INTEGER NOT NULL,
	time_issued 	TIMESTAMP DEFAULT CURRENT_TIMESTAMP NOT NULL,
	expires 		INTEGER NOT NULL,
	scope 			VARCHAR(255) DEFAULT NULL,
	revoked			INTEGER NOT NULL DEFAULT 0,
	code 			VARCHAR(128) NULL,
	PRIMARY KEY (token)
);
*/
