#ifndef UTILS_H_
#define UTILS_H_

#define DBHOST "change_poo"
#define DBNAME "change_poo"
#define DBUSER "change_poo"
#define DBPASS "change_poo"

#include "webapp.h"

char* read_file(char *filename);
int authenticate(char *username, char *password);
int is_authenticated();
char *get_session_username();
char *get_first_name(char *username);
char *get_last_name(char *username);
int is_admin(char *username);
int add_user(char *username, char *password, char *first_name, char *last_name, char *ssn, char is_admin);
int add_entry(char *username, char *day, char *minutes_worked);
int approve_entry(char *username, char *day);
void render_entries_json(response *res, char *username, char *start_date, char *end_date);
void dump_tables(response *res);

#endif
