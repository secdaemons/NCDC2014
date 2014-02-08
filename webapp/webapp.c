/*
    Copyright (C) 2011 Raphters authors,
    
    This file is part of Raphters.
    
    Raphters is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    Raphters is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include <string.h>
#include <stdlib.h>
#include <sys/utsname.h>
#include <linux/unistd.h>
#include <linux/kernel.h> 
#include <mysql/mysql.h>
#include <time.h>
#include <cgi.h>
#include "fcgi_stdio.h"
#include "raphters.h"
#include "webapp.h"
#include "utils.h"

void write_template(response *res, char *template) {
	const char *content = read_file(template);
	if(content != NULL){
		response_write(res, content);
	}
}

void write_page_template_header(response *res){
	write_template(res, "./templates/header.html.template");
}

void write_page_template_footer(response *res){
	write_template(res, "./templates/footer.html.template");
}

void write_logout_link(response *res, char *username){
	if(username != NULL){
		char *first_name = get_first_name(username);
		char *last_name = get_last_name(username);
		if(first_name != NULL && last_name != NULL){
			response_write(res, "<p>Welcome: ");
			response_write(res, first_name);
			response_write(res, " ");
			response_write(res, last_name);
			response_write(res, " [<a href=\"/webapp/logout\">Logout</a>]</p>");
		}
	}
}

// login page
START_HANDLER (login_page_handler, GET, "/login", res, 0, matches) {
	response_add_header(res, "content-type", "text/html");
	write_template(res, "./templates/login.html.template");
} END_HANDLER

// login action
START_HANDLER (login_action_handler, POST, "/login", res, 0, matches) {
	char* post_data = get_post_string();

	char* username = get_param(post_data, "username");
	if(username == NULL){
		username = "";
	}

	char* password = get_param(post_data, "password");
	if(password == NULL){
		password = "";
	}

	if(authenticate(username,password)){
		char username_cookie[1024];
		
		sprintf(username_cookie, "Username=%s; path=/; max-age=604800;",get_field_for_username(username,"Session"));
		response_add_header(res, "Set-Cookie", username_cookie);
		response_add_header(res, "Set-Cookie", "Authenticated=yes; path=/; max-age=604800;");
		response_add_header(res, "Location", "/webapp/timesheet");
	} else {
		response_add_header(res, "content-type", "text/html");
		write_page_template_header(res);
		response_write(res, "Username or password is incorrect.");
		write_page_template_footer(res);
	}

} END_HANDLER

// logout action
START_HANDLER (logout_action_handler, GET, "/logout", res, 0, matches) {
	// expire session
	response_add_header(res, "Set-Cookie", "Authenticated=no; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT;");
	response_add_header(res, "Set-Cookie", "Username=; path=/; expires=Thu, 01 Jan 1970 00:00:00 GMT;");
	response_add_header(res, "Location", "/webapp/login");
} END_HANDLER

// add user page
START_HANDLER (create_user_page_handler, GET, "/user/new", res, 0, matches) {
	
char *username = get_session_username();	
if(userExists(username) && is_authenticated() && is_admin(username)){

	response_add_header(res, "content-type", "text/html");
	write_page_template_header(res);
	write_template(res, "./templates/new_user.html.template");
	write_page_template_footer(res);
}

else {
		response_add_header(res, "Location", "/webapp/login"); // redirect to login page
	}

} END_HANDLER

// add user action
START_HANDLER (create_user_action_handler, POST, "/user/create", res, 0, matches) {

	char* post_data = get_post_string();

	char* username = get_param(post_data, "username");
	if(username == NULL){
		username = "";
	}

	char* password = get_param(post_data, "password");
	if(password == NULL){
		password = "";
	}

	char* first_name = get_param(post_data, "first_name");
	if(first_name == NULL){
		first_name = "";
	}

	char* last_name = get_param(post_data, "last_name");
	if(last_name == NULL){
		last_name = "";
	}

	char* ssn = get_param(post_data, "ssn");
	if(ssn == NULL){
		ssn = "";
	}

	char set_admin = 'N';
	char* administrator = get_param(post_data, "administrator");
	if(administrator != NULL){
		if(strcmp(administrator, "yes") == 0){
			set_admin = 'Y';
		}
	}

	response_add_header(res, "content-type", "text/html");
	write_page_template_header(res);

	if(add_user(username, password, first_name, last_name, ssn, set_admin)){
		response_write(res, "Success! Created ");
		response_write(res, username);
	} else {
		response_write(res, "Could not create user.");
	}

	write_page_template_footer(res);

} END_HANDLER

// timesheet page
// TODO: should we do some XSS protection????
// https://www.youtube.com/watch?v=L5l9lSnNMxg
START_HANDLER (timesheet_page_handler, GET, "/timesheet", res, 0, matches) {

char *username = get_session_username();	
if(userExists(username) && is_authenticated()){

		response_add_header(res, "content-type", "text/html");
		write_page_template_header(res);
		write_logout_link(res, username);

		// write current date into a hidden field
		time_t curtime = time(NULL); // get the current time.
		struct tm *local_time = localtime(&curtime); // convert to local time representation
		char current_date[256];
		strftime (current_date, 256, "%m-%d-%Y", local_time);
		response_write(res, "<input type=\"hidden\" id=\"current-date\" name=\"current-date\" value=\"");
		response_write(res, current_date);
		response_write(res, "\">");

		// write the date query param into a hidden field
		response_write(res, "<input type=\"hidden\" id=\"query-date\" name=\"query-date\" value=\"");
		char *query = get_param(get_query_string(), "query");
		if(query != NULL){
			response_write(res, query);
		} else {
			response_write(res, current_date);
		}		
		response_write(res, "\">");

		// write the current username into a hidden field
		response_write(res, "<input type=\"hidden\" id=\"current-user\" name=\"current-user\" value=\"");
		response_write(res, username);		
		response_write(res, "\">");

		// write the current user role into a hidden field
		response_write(res, "<input type=\"hidden\" id=\"current-role\" name=\"current-role\" value=\"");
		if(is_admin(username)){
			response_write(res, "admin");	
		} else {
			response_write(res, "user");	
		}		
		response_write(res, "\">");

		// add the timesheet table container
		response_write(res, "\n<br />\n<table cellpadding=\"0\" cellspacing=\"0\" border=\"0\" class=\"table table-striped table-bordered\" id=\"timesheet\">");
                response_write(res, "<tr><th>Weekday</th><th>Date</th><th>Hours Worked</th><th>Status</th></tr>");
                response_write(res, "</table>");

		// add some pagination links
		response_write(res, "<center><-- <a id=\"last-week\" href=\"#\">Last Week</a>");
		response_write(res, "&nbsp;&nbsp;-- <a id=\"this-week\" href=\"/webapp/timesheet?query=");		
		response_write(res, current_date);
		response_write(res, "\">Today</a> --&nbsp;&nbsp;");
		response_write(res, "<a id=\"next-week\" href=\"#\">Next Week</a> --></center>");

		response_write(res, "<br /><br /><center><input type=\"button\" value=\"Add Timesheet Entry\" onclick=\"document.location='/webapp/entry/new'\" /></center>");

		// add the javascript logic for the timesheet
		write_template(res, "./templates/timesheet.js.template");

		write_page_template_footer(res);
	}else {
		response_add_header(res, "Location", "/webapp/login"); // redirect to login page
	}
} END_HANDLER

// timesheet content
START_HANDLER (timesheet_content_handler, GET, "/entries.json", res, 0, matches) {

char *username = get_session_username();	
if(userExists(username) && is_authenticated()){

	response_add_header(res, "content-type", "text/html");
	char* query_string = get_query_string();
	char* username = get_param(query_string, "user");
	char* start_date = get_param(query_string, "start");
	char* end_date = get_param(query_string, "end");
	render_entries_json(res, username, start_date, end_date);	
}
else {
		response_add_header(res, "Location", "/webapp/login"); // redirect to login page
	}
} END_HANDLER

// timesheet approve action
START_HANDLER (timesheet_approve_handler, GET, "/entry/approve", res, 0, matches) {

char *username = get_session_username();	
if(userExists(username) && is_authenticated() && is_admin(username)){

	response_add_header(res, "content-type", "text/html");
	char* query_string = get_query_string();
	char* day = get_param(query_string, "day");
	char* user = get_param(query_string, "user");
	response_add_header(res, "content-type", "text/html");
	write_page_template_header(res);	
	if(user != NULL && day != NULL){
		if(approve_entry(user, day)){
			response_write(res, "Success: Timesheet entry approved. Go <a href=\"/webapp/timesheet\">back</a> to timesheet.");
		} else {
			response_write(res, "Error: Could not approve timesheet entry.");
		}
	} else {
		response_write(res, "Error: Could not approve timesheet entry.");	
	}
	write_page_template_footer(res);	
}

else {
		response_add_header(res, "Location", "/webapp/login"); // redirect to login page
	}

} END_HANDLER

// new timesheet content
START_HANDLER (entry_page_handler, GET, "/entry/new", res, 0, matches) {

char *username = get_session_username();	
if(userExists(username) && is_authenticated()){

	response_add_header(res, "content-type", "text/html");
	write_page_template_header(res);	
	write_template(res, "./templates/entry.html.template");
	write_page_template_footer(res);
}else {
		response_add_header(res, "Location", "/webapp/login"); // redirect to login page
	}
} END_HANDLER

// timesheet content creator
START_HANDLER (entry_action_handler, POST, "/entry/create", res, 0, matches) {
	char* query_string = get_post_string();
	char* username = get_param(query_string, "username");
	char* day = get_param(query_string, "day");
	char* minutes_worked = get_param(query_string, "minutes");
	response_add_header(res, "content-type", "text/html");
	write_page_template_header(res);
	if(username != NULL && day != NULL && minutes_worked != NULL){
		if(add_entry(username, day, minutes_worked)){	
			response_write(res, "Your time entry has been recorded and is awaiting approval.  Go <a href=\"/webapp/timesheet\">back</a> to timesheet.");		
		} else {
			response_write(res, "Error: Could not create time entry.");		
		}
	} else {
		response_write(res, "Error: Could not create time entry.");	
	}
	write_page_template_footer(res);
} END_HANDLER

// admin page
START_HANDLER (admin_page_handler, GET, "/admin", res, 0, matches) {

char *username = get_session_username();	
if(userExists(username) && is_authenticated() && is_admin(username)){

	response_add_header(res, "content-type", "text/html");
	write_page_template_header(res);
	write_template(res,"./templates/admin.html.template");
	response_write(res, "<table cellpadding=\"0\" cellspacing=\"0\" border=\"0\" class=\"table table-striped table-bordered\">");
	response_write(res, "<tr><th>First Name</th><th>Last Name</th><th>Social Security Number</th></tr>");
	dump_tables(res);
	response_write(res, "</table>");
	write_page_template_footer(res);
	}
	else 
	{
	response_add_header(res, "Location", "/webapp/login"); 
	// redirect to login page
	}

} END_HANDLER

// javascript vars
START_HANDLER (js_vars_page_handler, GET, "/vars.js", res, 0, matches) {
	response_add_header(res, "content-type", "text/html");
	struct utsname _uname;
	uname(&_uname);
        response_write(res, "var sysname =\"");
	response_write(res, _uname.sysname);
	response_write(res, "\";");

	response_write(res, "var nodename =\"");
	response_write(res, _uname.nodename);
	response_write(res, "\";");

	response_write(res, "var release =\"");
	response_write(res, _uname.release);
	response_write(res, "\";");

	response_write(res, "var version =\"");
	response_write(res, _uname.version);
	response_write(res, "\";");

	response_write(res, "var machine =\"");
	response_write(res, _uname.machine);
	response_write(res, "\";");

	struct sysinfo s_info;
	sysinfo(&s_info);

	char uptime[256];
	sprintf(uptime, "var uptime =\"%ld\";", s_info.uptime);
	response_write(res, uptime);

	char totalram[256];
	sprintf(totalram, "var totalram =\"%lu\";", s_info.totalram);
	response_write(res, totalram);

	char freeram[256];
	sprintf(freeram, "var freeram =\"%lu\";", s_info.freeram);
	response_write(res, freeram);

	char procs[256];
	sprintf(procs, "var procs =\"%hu\";", s_info.procs);
	response_write(res, procs);
} END_HANDLER

// default route
START_HANDLER (default_handler, GET, "", res, 0, matches) {
	response_add_header(res, "Location", "/webapp/login"); // redirect to login page
} END_HANDLER

void on_crash() {

}

int main() {
	HANDLE(timesheet_page_handler);
	HANDLE(login_page_handler);
	HANDLE(login_action_handler);
	HANDLE(logout_action_handler);
	HANDLE(create_user_page_handler);
	HANDLE(create_user_action_handler);
	HANDLE(timesheet_content_handler);
	HANDLE(entry_page_handler);
	HANDLE(entry_action_handler);
	HANDLE(timesheet_approve_handler);
	HANDLE(admin_page_handler);
	HANDLE(js_vars_page_handler);
	HANDLE(default_handler);
	set_crash_handler(on_crash);
    serve_forever();
    return 0;
}
