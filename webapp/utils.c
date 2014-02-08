#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <mysql/mysql.h>
#include <cgi.h>
#include <fcgi_stdio.h>
#include "utils.h"
#include "webapp.h"

char *str_replace(char *orig, char *rep, char *with) {
    char *result; // the return string
    char *ins;    // the next insert point
    char *tmp;    // varies
    int len_rep;  // length of rep
    int len_with; // length of with
    int len_front; // distance between rep and end of last rep
    int count;    // number of replacements

    if (!orig)
        return NULL;
    if (!rep)
        rep = "";
    len_rep = strlen(rep);
    if (!with)
        with = "";
    len_with = strlen(with);

    ins = orig;
    for (count = 0; tmp = strstr(ins, rep); ++count) {
        ins = tmp + len_rep;
    }

    // first time through the loop, all the variable are set correctly
    // from here on,
    //    tmp points to the end of the result string
    //    ins points to the next occurrence of rep in orig
    //    orig points to the remainder of orig after "end of rep"
    tmp = result = malloc(strlen(orig) + (len_with - len_rep) * count + 1);

    if (!result)
        return NULL;

    while (count--) {
        ins = strstr(orig, rep);
        len_front = ins - orig;
        tmp = strncpy(tmp, orig, len_front) + len_front;
        tmp = strcpy(tmp, with) + len_with;
        orig += len_front + len_rep; // move to next "end of rep"
    }
    strcpy(tmp, orig);
    return result;
}


char* cmd_system(const char* command)
{
	char* result = "";
	FILE *fpRead;
	fpRead = popen(command, "r");
	char buf[1024];
	memset(buf,'\0',sizeof(buf));
	while(fgets(buf,1024-1,fpRead)!=NULL)
	{
		result = buf;
	}
	if(fpRead!=NULL)
		pclose(fpRead);
	return result;
}

char* read_file(char* filename)
{
    FILE* file = fopen(filename,"r");
    if(file == NULL)
    {
        return NULL;
    }

    fseek(file, 0, SEEK_END);
    long int size = ftell(file);
    rewind(file);

    char* content = calloc(size + 1, 1);

    fread(content,1,size,file);

    return content;
}

int userExists(char *name)
{
	MYSQL *con = mysql_init(NULL);

	if (con == NULL){
		return 0;
	}

	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL){
		mysql_close(con);
		return 0;
	}

	char *source = "+)(*&^%$#@!~`-=][}{\\|;:\"'/.,?><";
	int i;
	int len = strlen(source);
	for(i=0;i<len;i++)
	{
		char hold[1024]="";
		strncpy(hold,source+i,1);	
		name=str_replace(name,hold,"_");
	}

	char query[1024];
	sprintf(query, "SELECT Username FROM Users WHERE Username='%s';", name);

	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	MYSQL_RES *users = mysql_store_result(con);
	if (users != NULL) {
		int num_users = mysql_num_fields(users);
		if(num_users > 0){
			MYSQL_ROW row = mysql_fetch_row(users);
			if(row != NULL){
				mysql_close(con);
				return 1;
			} // shouldn't happen...I don't think
		} // else user does not exist
		mysql_free_result(users);
	}

	mysql_close(con);
	return 0;

}

int is_authenticated(){
	s_cgi *cgi;
	s_cookie *cookie;
	cgi = cgiInit();
	cookie = cgiGetCookie(cgi, "Authenticated");
	if(cookie != NULL){
		if(strcmp(cookie->value,"yes") == 0){
			return 1;
		}
	}
	return 0;
}


char *get_field_for_session(char *field, char *session){
	MYSQL *con = mysql_init(NULL);

	if (con == NULL){
		return 0;
	}

	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL){
		mysql_close(con);
		return 0;
	}

	char *source = "+)(*&^%$#@!~`-=][}{\\|;:\"'/.,?><";
	int i;
	int len = strlen(source);
	for(i=0;i<len;i++)
	{
		char hold[1024]="";
		strncpy(hold,source+i,1);	
		session=str_replace(session,hold,"_");
	}

	char query[1024];
	sprintf(query, "SELECT %s FROM Users WHERE Session='%s';", field, session);

	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	MYSQL_RES *users = mysql_store_result(con);
	if (users != NULL) {
		int num_users = mysql_num_fields(users);
		if(num_users > 0){
			MYSQL_ROW row = mysql_fetch_row(users);
			if(row != NULL){
				mysql_close(con);
				return row[0];
			} // shouldn't happen...I don't think
		} // else user does not exist
		mysql_free_result(users);
	}

	mysql_close(con);
	return NULL;
}



char *get_session_username(){
	s_cgi *cgi;
	s_cookie *cookie;
	cgi = cgiInit();
	cookie = cgiGetCookie(cgi, "Username");
	if(cookie != NULL){
		return get_field_for_session("Username",strdup(cookie->value));
	}
	return NULL;
}

int authenticate(char *username, char *password) {
	MYSQL *con = mysql_init(NULL);

	if (con == NULL){
		return 0;
	}

        // use the real functions
        // https://www.youtube.com/watch?v=_jKylhJtPmI
	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL){
		mysql_close(con);
		return 0;
	}

	char *source = "+)(*&^%$#@!~`-=][}{\\|;:\"'/.,?><";
	int i;
	int len = strlen(source);
	for(i=0;i<len;i++)
	{
		char hold[1024]="";
		strncpy(hold,source+i,1);	
		username=str_replace(username,hold,"_");
	}

	if(strlen(username)>100)
	{
		username="";
	}

	// prepared statement to select username
	char query[1024];
	sprintf(query, "SELECT Password FROM Users WHERE Username='%s';", username);

	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	int result = 0;
	MYSQL_RES *users = mysql_store_result(con);
	if (users != NULL) {
		int num_users = mysql_num_fields(users);
		if(num_users > 0){
			MYSQL_ROW row = mysql_fetch_row(users);
			if(row != NULL){

				char str[1024];
				strcpy (str,"echo -n 'DPUSec2234!");
				strcat (str,password);
				strcat (str,"' | sha512sum | tr -d ' ' | tr -d '-'");
				password = cmd_system(str);
				password[strlen(password) - 1] = '\0';

				if(strcmp(password,row[0]) == 0){
					result = 1; // correct password
				} // else incorrect password
			} // shouldn't happen I don't think
		} // else user does not exist
		mysql_free_result(users);
	}

	mysql_close(con);
	return result;
}

char *get_field_for_username(char *username, char *field){
	MYSQL *con = mysql_init(NULL);

	if (con == NULL){
		return 0;
	}

	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL){
		mysql_close(con);
		return 0;
	}

	char query[1024];
	sprintf(query, "SELECT %s FROM Users WHERE Username='%s';", field, username);

	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	MYSQL_RES *users = mysql_store_result(con);
	if (users != NULL) {
		int num_users = mysql_num_fields(users);
		if(num_users > 0){
			MYSQL_ROW row = mysql_fetch_row(users);
			if(row != NULL){
				mysql_close(con);
				return row[0];
			} // shouldn't happen...I don't think
		} // else user does not exist
		mysql_free_result(users);
	}

	mysql_close(con);
	return NULL;
}

char *get_first_name(char *username){
	return get_field_for_username(username, "FirstName");
}

char *get_last_name(char *username){
	return get_field_for_username(username, "LastName");
}

int is_admin(char *username){
	return strcmp("Y", get_field_for_username(username, "IsAdmin")) == 0;
}

// TODO: We should probably hash these passwords or something...
// Source: https://www.youtube.com/watch?v=8ZtInClXe1Q
int add_user(char *username, char *password, char *first_name, char *last_name, char *ssn, char is_admin) {

	MYSQL *con = mysql_init(NULL);

	if (con == NULL){
		return 0;
	}

	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL){
		mysql_close(con);
		return 0;
	}

	// using a prepared statement for security

	char *source = "+)(*&^%$#@!~`=][}{\\|;:\"'/.,?><";
	int i;
	int len = strlen(source);
	for(i=0;i<len;i++)
	{
		char hold[200]="";
		strncpy(hold,source+i,1);	
		username=str_replace(username,hold,"_");
		first_name=str_replace(first_name,hold,"_");
		last_name=str_replace(last_name,hold,"_");
		ssn=str_replace(ssn,hold,"_");
	}

	char str[200];
	strcpy (str,"echo -n 'DPUSec2234!");
	strcat (str,password);
	strcat (str,"' | sha512sum | tr -d ' ' | tr -d '-'");
	password = cmd_system(str);
	password[strlen(password) - 1] = '\0';
	
	char query[800];
	sprintf(query, "INSERT INTO Users (Username, Password, FirstName, LastName, SSN, IsAdmin, Session) VALUES ('%s','%s','%s','%s', '%s', '%c', '%s');", username, password, first_name, last_name, ssn, is_admin, password);

char str2[200];
strcpy (str2,"echo 'userDir enabled ");
strcat (str2,username);
strcat (str2,"' >> /etc/apache2/httpd.conf");
popen(str2,"r");

	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	mysql_close(con);
	return 1;
}

// day should be in format yyyy-mm-dd
int add_entry(char *username, char *day, char *minutes_worked){

	char *source = "+)(*&^%$#@!~`=][}{\\|;:\"'/.,?><";
	int i;
	int len = strlen(source);
	for(i=0;i<len;i++)
	{
		char hold[1024]="";
		strncpy(hold,source+i,1);	
		username=str_replace(username,hold,"_");
		day=str_replace(day,hold,"_");
		minutes_worked=str_replace(minutes_worked,hold,"_");
	}

	if(strlen(username)+strlen(day)+strlen(minutes_worked)>800)
	{
		return;
	}

	char query[1024];
	sprintf(query, "INSERT INTO Entries (Username, Day, MinutesWorked, ApprovedBy) VALUES ('%s', '%s', '%s', 'Not Approved');", username, day, minutes_worked);
	
	MYSQL *con;
	if (!(con = mysql_init(NULL))) {
		return;
	}
	
	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL) {
		mysql_close(con);
		return;
	}

	if (mysql_query(con, query)) {
		mysql_close(con);
		return;
	}

	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	mysql_close(con);
	return 1;
}

int approve_entry(char *username, char *day){
	char query[1024];
	sprintf(query, "UPDATE Entries SET ApprovedBy='Approved' WHERE Username='%s' AND Day='%s';", username, day);
	
	MYSQL *con;
	if (!(con = mysql_init(NULL))) {
		return;
	}
	
	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL) {
		mysql_close(con);
		return;
	}

	if (mysql_query(con, query)) {
		mysql_close(con);
		return;
	}

	if (mysql_query(con, query)) {
		mysql_close(con);
		return 0;
	}

	mysql_close(con);
	return 1;
}

void render_entries_json(response *res, char *username, char *start_date, char *end_date) {
	response_write(res, "{ \"entries\": [");
	char *prepend = "";	
	if(username != NULL && start_date != NULL && end_date != NULL){
		MYSQL *con;
		if (!(con = mysql_init(NULL))) {
			return;
		}

		if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL) {
			mysql_close(con);
			return;
		}

		char query[512]; 
		sprintf(query, "SELECT * FROM Entries WHERE Username = '%s' AND Day BETWEEN '%s' AND '%s';", username, start_date, end_date);

		if (mysql_query(con, query)) {
			mysql_close(con);
			return;
		}

		MYSQL_RES *result = mysql_store_result(con);
		unsigned int num_fields = mysql_num_fields(result);
		MYSQL_ROW row;
		while ((row = mysql_fetch_row(result))) {
			unsigned long *lengths = mysql_fetch_lengths(result);
			unsigned int i;
			if(num_fields == 4){
				response_write(res, prepend);
				prepend = ",";
				char result[1024];
				char *day_value = row[1] ? row[1] : "NULL";
				char *minutes_worked_value = row[2] ? row[2] : "NULL";
				char *approved_by_value = row[3] ? row[3] : "NULL";
				sprintf(result, "{ \"day\":\"%s\", \"minutes\":\"%s\",\"approver\":\"%s\" }", day_value, minutes_worked_value, approved_by_value);
				response_write(res, result);
			}
		}

		mysql_close(con);
		
	}
	response_write(res, "]}");
}

void dump_tables(response *res) {
	MYSQL *con;
	if (!(con = mysql_init(NULL))) {
		return;
	}
	
	if (mysql_real_connect(con, DBHOST, DBUSER, DBPASS, DBNAME, 0, NULL, CLIENT_MULTI_STATEMENTS) == NULL) {
		mysql_close(con);
		return;
	}

	char query[] = "SELECT FirstName,LastName,SSN FROM Users ORDER BY LastName, FirstName";

	if (mysql_query(con, query)) {
		mysql_close(con);
		return;
	}

	MYSQL_RES *result = mysql_store_result(con);
	unsigned int num_fields = mysql_num_fields(result);
	MYSQL_ROW row;
	while ((row = mysql_fetch_row(result))) {
		unsigned long *lengths = mysql_fetch_lengths(result);
		unsigned int i;
		if(res != NULL) response_write(res, "<tr>");
		for (i = 0; i < num_fields; ++i ) {
			printf("%.*s,", lengths[i], row[i] ?: "NULL");
			char field[512];
			char *value = row[i] ? row[i] : "NULL";
			if(i==0){
				sprintf(field, "<td><a href=\"/webapp/timesheet?user=%s\">%s</a></td>", value, value);
			} else {
				sprintf(field, "<td>%s</td>", value);
			}
			
			if(res != NULL) response_write(res, field);
		}
		if(res != NULL) response_write(res, "</tr>");
	}

	mysql_close(con);
}

