----------------------------------------------------------------
----------------------------------------------------------------
--
-- IGNITION CONTROL TOPOLOGY SCHEMA
-- Copywrite (c) Cplane, Inc. 2002 - All Rights Reserved
--
-- *** GENERATED CODE - DO NOT EDIT ***
--
----------------------------------------------------------------
----------------------------------------------------------------

--------------------------------------------------------------------------------
--
-- create table and sequence [ cp_wf_java_class ] in tablespace [ CP_TABs ]
--
--------------------------------------------------------------------------------
CREATE TABLE cp_wf_java_class (
	name VARCHAR(255) NOT NULL,
	CONSTRAINT cp_wf_java_class$pk PRIMARY KEY (name),
	byte_code BLOB NOT NULL,
	description VARCHAR(1000) NULL
) TABLESPACE CP_TABM ;
	-- cp_wf_java_class

--------------------------------------------------------------------------------
--
-- create table and sequence [ cp_wf_script_file ] in tablespace [ CP_TABs ]
--
--------------------------------------------------------------------------------
CREATE TABLE cp_wf_script_file (
	script_name VARCHAR(255) NOT NULL,
	CONSTRAINT cp_wf_script_file$pk PRIMARY KEY (script_name),
	script_type_enum VARCHAR(255),
	script_text BLOB NULL,
	description VARCHAR(1000) NULL
) TABLESPACE CP_TABM ;
	-- cp_wf_script_file
CREATE SEQUENCE cp_wf_script_file_seq increment by 1 start with 100;

CREATE INDEX cp_wf_script_file$ScnumNme ON cp_wf_script_file ( script_type_enum, script_name) TABLESPACE CP_INDS;


--------------------------------------------------------------------------------
--
-- create table and sequence [ cp_wf_node ] in tablespace [ CP_TABm ]
--
--------------------------------------------------------------------------------
CREATE TABLE cp_wf_node (
	id NUMBER(19) NOT NULL,
	CONSTRAINT cp_wf_node$pk PRIMARY KEY (id),
	row_version NUMBER(10) DEFAULT 0 NOT NULL,
	CONSTRAINT cp_wf_node$rv UNIQUE (id, row_version),
	name VARCHAR(255) NULL,
	model_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_node, model_fk, cp_core_model, id, m)
	FOREIGN KEY (model_fk) REFERENCES cp_core_model (id),
	java_class_name VARCHAR(255) DEFAULT 'java.lang.Object' NOT NULL,
	seq_num NUMBER(5) DEFAULT 0 NOT NULL,
	-- STRIPE(cp_wf_node, created_by_fk, cp_admin_access, access_id, m)
	created_by_fk NUMBER(19) NOT NULL,
	-- STRIPE(cp_wf_node, modified_by_fk, cp_admin_access, access_id, m)
	modified_by_fk NUMBER(19) NOT NULL,
	created_date DATE DEFAULT SYSDATE NOT NULL,
	last_modified_date DATE DEFAULT SYSDATE NOT NULL,
	model_cat_fk NUMBER(19) NULL,
	--FOREIGN_KEY(cp_wf_node, model_cat_fk, cp_core_model_cat, id, l)
	FOREIGN KEY (model_cat_fk) REFERENCES cp_core_model_cat (id),
	parent_model_cat_fk NUMBER(19) NULL,
	--FOREIGN_KEY(cp_wf_node, parent_model_cat_fk, cp_core_model_cat, id, l)
	FOREIGN KEY (parent_model_cat_fk) REFERENCES cp_core_model_cat (id),
	parent_node_name VARCHAR(255),
	CONSTRAINT cp_wf_node$uq UNIQUE (model_cat_fk, name, parent_model_cat_fk, parent_node_name),
	wf_java_class_name VARCHAR(255) NULL,
	--FOREIGN_KEY(cp_wf_node, wf_java_class_name, cp_wf_java_class, name, m)
	FOREIGN KEY (wf_java_class_name) REFERENCES cp_wf_java_class (name),
	script_name VARCHAR(255) NULL,
	--FOREIGN_KEY(cp_wf_node, script_name, cp_wf_script_file, script_name, m)
	FOREIGN KEY (script_name) REFERENCES cp_wf_script_file (script_name),
	node_type_enum VARCHAR(255),
	user_label VARCHAR(255),
	find_method_name VARCHAR(255),
	ejb_script_method VARCHAR(255) NULL,
	ejb_home_intf VARCHAR(255) NULL,
	ejb_remote_intf VARCHAR(255) NULL,
	ejb_jndi_name VARCHAR(255) NULL,
	ejb_create_param_size NUMBER(5),
	ejb_find_param_size NUMBER(5),
	method_arg_offset NUMBER(5),
	undo_method_name VARCHAR(255),
	description VARCHAR(1000)
) TABLESPACE CP_TABM;
	-- cp_wf_node
	CREATE SEQUENCE cp_wf_node_seq increment by 1 start with 100;

	CREATE INDEX cp_wf_node$NameId ON cp_wf_node (name,id) TABLESPACE CP_INDM;


--------------------------------------------------------------------------------
--
-- create table and sequence [ cp_wf_node_value ] in tablespace [ CP_TABm ]
--
--------------------------------------------------------------------------------
CREATE TABLE cp_wf_node_value (
	owner_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_node_value, owner_fk, cp_wf_node, id, m)
	FOREIGN KEY (owner_fk) REFERENCES cp_wf_node (id) ON DELETE CASCADE,
	name VARCHAR(255) NOT NULL,
	sequence_num NUMBER(5),
	CONSTRAINT cp_wf_node_value$pk PRIMARY KEY (owner_fk, name, sequence_num),
	string_value VARCHAR(4000) NULL,
	integer_value NUMBER(10) NULL,
	long_value NUMBER(20) NULL,
	float_value NUMBER NULL,
	datetime_value DATE NULL,
	boolean_value VARCHAR(2) NULL,
	raw_value RAW(2000) NULL
	) TABLESPACE CP_TABM;
	-- cp_wf_node
CREATE INDEX cp_wf_node$JnmeNmeId ON cp_wf_node (java_class_name, name, id) TABLESPACE CP_INDM;


--------------------------------------------------------------------------------
--
-- create table and sequence [ cp_wf_param ] in tablespace [ CP_TABm ]
--
--------------------------------------------------------------------------------
CREATE TABLE cp_wf_param (
	id NUMBER(19) NOT NULL,
	CONSTRAINT cp_wf_param$pk PRIMARY KEY (id),
	model_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_param, model_fk, cp_wf_node, id, m)
	FOREIGN KEY (model_fk) REFERENCES cp_wf_node (id) ON DELETE CASCADE,
	name VARCHAR(255),
	CONSTRAINT cp_wf_param$name UNIQUE (model_fk, name),
	CONSTRAINT cp_wf_param$cp_wf_param$rv UNIQUE (model_fk, id),
	is_dynamic VARCHAR(2) DEFAULT 'T' NOT NULL CHECK (is_dynamic IN ('T','F')),
	is_collection VARCHAR(2) DEFAULT 'F' NOT NULL CHECK (is_collection IN ('T','F')),
	is_required VARCHAR(2) DEFAULT 'T' NOT NULL CHECK (is_required IN ('T','F')),
	java_class_constraint VARCHAR(255) NULL,
	expression_constraint VARCHAR(4000) NULL,
	enum_constraint NUMBER(19) NULL,
	--FOREIGN_KEY(cp_wf_param, enum_constraint, cp_core_enum, id, m)
	FOREIGN KEY (enum_constraint) REFERENCES cp_core_enum (id),
	prompt VARCHAR(255) NOT NULL,
	is_displayable VARCHAR(2) DEFAULT 'T' NOT NULL CHECK (is_displayable IN ('T','F')),
	is_editable VARCHAR(2) DEFAULT 'F' NOT NULL CHECK (is_editable IN ('T','F')),
	is_password VARCHAR(2) DEFAULT 'F' NOT NULL CHECK (is_password IN ('T','F')),
	is_primary VARCHAR(2) DEFAULT 'F' NOT NULL CHECK (is_primary IN ('T','F')),
	display_order NUMBER(10),
	editor_type VARCHAR(255),
	is_undo_parameter VARCHAR(2) DEFAULT 'F' NOT NULL CHECK (is_undo_parameter IN ('T','F')),
	parameter_type_enum VARCHAR(255),
	CONSTRAINT cp_wf_param$display UNIQUE (name, model_fk, display_order, parameter_type_enum)
) TABLESPACE CP_TABM;
	-- cp_wf_param

	CREATE SEQUENCE cp_wf_param_seq increment by 1 start with 100;




--------------------------------------------------------------------------------
--
-- create table and sequence [ cp_wf_param_default_value ] in tablespace [ CP_TABm ]
--
--------------------------------------------------------------------------------
CREATE TABLE cp_wf_param_default_value (
	owner_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_param_default_value, owner_fk, cp_wf_param, id, m)
	FOREIGN KEY (owner_fk) REFERENCES cp_wf_param (id) ON DELETE CASCADE,
	name VARCHAR(255) NOT NULL,
	sequence_num NUMBER(5),
	CONSTRAINT cp_wf_param_default_value$pk PRIMARY KEY (owner_fk, name, sequence_num),
	string_value VARCHAR(4000) NULL,
	integer_value NUMBER(10) NULL,
	long_value NUMBER(20) NULL,
	float_value NUMBER NULL,
	datetime_value DATE NULL,
	boolean_value VARCHAR(2) NULL,
	raw_value RAW(2000) NULL
	) TABLESPACE CP_TABM;
	-- cp_wf_param

--------------------------------------------------------------------------------
--
-- create table and sequence [ cp_wf_ref ] in tablespace [ CP_TABm ]
--
--------------------------------------------------------------------------------
CREATE TABLE cp_wf_ref (
	id NUMBER(19) NOT NULL,
	CONSTRAINT cp_wf_ref$pk PRIMARY KEY (id),
	name VARCHAR(255) NOT NULL,
	user_label VARCHAR(255),
	java_class_name VARCHAR(4000) NULL,
	wf_node_parent_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_ref, wf_node_parent_fk, cp_wf_node, id, m)
	FOREIGN KEY (wf_node_parent_fk) REFERENCES cp_wf_node (id) ON DELETE CASCADE,
	wf_node_child_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_ref, wf_node_child_fk, cp_wf_node, id, m)
	FOREIGN KEY (wf_node_child_fk) REFERENCES cp_wf_node (id),
	CONSTRAINT cp_wf_ref$name UNIQUE (wf_node_parent_fk, wf_node_child_fk, name),
	wf_node_child_java_class_name VARCHAR(4000) NOT NULL,
	is_start VARCHAR(2) DEFAULT 'F' NOT NULL CHECK (is_start IN ('T','F')),
	is_end VARCHAR(2) DEFAULT 'F' NOT NULL CHECK (is_end IN ('T','F')),
	switch_expr VARCHAR(4000) NULL,
	loop_is_concurrent VARCHAR(2) DEFAULT 'F' NOT NULL CHECK (loop_is_concurrent IN ('T','F')),
	loop_param_name VARCHAR(4000) NULL,
	loop_integer_from NUMBER(20) NULL,
	loop_integer_to NUMBER(20) NULL,
	description VARCHAR(1000) NULL
) TABLESPACE CP_TABM;
	-- cp_wf_ref
CREATE SEQUENCE cp_wf_ref_seq increment by 1 start with 100;


--------------------------------------------------------------------------------
--
-- create table and sequence [ cp_wf_transition ] in tablespace [ CP_TABm ]
--
--------------------------------------------------------------------------------
CREATE TABLE cp_wf_transition (
	id NUMBER(19) NOT NULL,
	CONSTRAINT cp_wf_transition$pk PRIMARY KEY (id),
	name VARCHAR(255) NULL,
	CONSTRAINT cp_wf_transition$uqname UNIQUE (id, name),
	parent_node_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_transition, parent_node_fk, cp_wf_node, id, m)
	FOREIGN KEY (parent_node_fk) REFERENCES cp_wf_node (id) ON DELETE CASCADE,
	from_ref_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_transition, from_ref_fk, cp_wf_ref, id, m)
	FOREIGN KEY (from_ref_fk) REFERENCES cp_wf_ref (id) ON DELETE CASCADE,
	to_ref_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_transition, to_ref_fk, cp_wf_ref, id, m)
	FOREIGN KEY (to_ref_fk) REFERENCES cp_wf_ref (id) ON DELETE CASCADE,
	switch_trans_type_enum VARCHAR(255),
	description VARCHAR(1000) NULL
) TABLESPACE CP_TABM;
	-- cp_wf_transition
CREATE SEQUENCE cp_wf_transition_seq increment by 1 start with 100;


--------------------------------------------------------------------------------
--
-- create table and sequence [ cp_wf_condition ] in tablespace [ CP_TABm ]
--
--------------------------------------------------------------------------------
CREATE TABLE cp_wf_condition (
	id NUMBER(19) NOT NULL,
	CONSTRAINT cp_wf_condition$pk PRIMARY KEY (id),
	type_enum VARCHAR(255),
	wf_node_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_condition, wf_node_fk, cp_wf_node, id, m)
	FOREIGN KEY (wf_node_fk) REFERENCES cp_wf_node (id) ON DELETE CASCADE,
	constraint_expr VARCHAR(4000) NULL,
	description VARCHAR(1000) NULL
) TABLESPACE CP_TABM;
	-- cp_wf_condition
CREATE SEQUENCE cp_wf_condition_seq increment by 1 start with 100;


--------------------------------------------------------------------------------
--
-- create table and sequence [ cp_wf_name_map ] in tablespace [ CP_TABm ]
--
--------------------------------------------------------------------------------
CREATE TABLE cp_wf_name_map (
	l_value VARCHAR(255) NOT NULL,
	r_value VARCHAR(255) NOT NULL,
	parent_node_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_name_map, parent_node_fk, cp_wf_node, id, m)
	FOREIGN KEY (parent_node_fk) REFERENCES cp_wf_node (id) ON DELETE CASCADE,
	CONSTRAINT cp_wf_name_map$pk PRIMARY KEY (parent_node_fk, l_value, r_value),
	transition_fk NUMBER(19) NULL,
	--FOREIGN_KEY(cp_wf_name_map, transition_fk, cp_wf_transition, id, m)
	FOREIGN KEY (transition_fk) REFERENCES cp_wf_transition (id) ON DELETE CASCADE,
	description VARCHAR(1000) NULL
) TABLESPACE CP_TABM;
	-- cp_wf_name_map

--------------------------------------------------------------------------------
--
-- create table and sequence [ cp_wf_execution ] in tablespace [ CP_TABm ]
--
--------------------------------------------------------------------------------
CREATE TABLE cp_wf_execution (
	id NUMBER(19) NOT NULL,
	CONSTRAINT cp_wf_execution$pk PRIMARY KEY (id),
	node_fk NUMBER(19) NOT NULL,
	--FOREIGN_KEY(cp_wf_execution, node_fk, cp_wf_node, id, m)
	FOREIGN KEY (node_fk) REFERENCES cp_wf_node (id) ON DELETE CASCADE,
	-- STRIPE(cp_wf_execution, created_by_fk, cp_admin_access, access_id, m)
	created_by_fk NUMBER(19) NOT NULL,
	-- STRIPE(cp_wf_execution, modified_by_fk, cp_admin_access, access_id, m)
	modified_by_fk NUMBER(19) NOT NULL,
	created_date DATE DEFAULT SYSDATE NOT NULL,
	last_modified_date DATE DEFAULT SYSDATE NOT NULL,
	-- STRIPE(cp_wf_execution, provider_fk, cp_cust_domain, id, m)
	provider_fk NUMBER(19) NOT NULL,
	-- STRIPE(cp_wf_execution, customer_fk, cp_cust_domain, id, m)
	customer_fk NUMBER(19) NOT NULL,
	serialized_execution BLOB NOT NULL
) TABLESPACE CP_TABM;
	-- cp_wf_execution
CREATE SEQUENCE cp_wf_execution_seq increment by 1 start with 100;

