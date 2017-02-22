--create--

create table if not exists account(
	id varchar(36) not null primary key,
	username varchar(50) not null,
	password varchar(50) not null,
	enabled boolean not null
)

create table if not exists role(
	id varchar(36) not null primary key,
	name varchar(50) not null,
	desc varchar(200) not null
)

create table if not exists user_role(
	account_id varchar(36) not null,
	role_id varchar(36) not null,
	foreign key(account_id) references account(id),
	foreign key(role_id) references role(id),
	primary key (user_id, role_id)
);

craete table if not exists app(
	id varchar(36) not null primary key,
	name varchar(50) not null,
	desc varchar(200) not null,
	key varchar(100) not null
)

--init--
insert IGNORE into user values(1,'demo', 'demo', true);
insert IGNORE into role values(2,'USER', '普通用户');
insert IGNORE into user_role values(1,2);
insert ignore into app values(3,'外部系统1','外部系统设置');