#ifndef _CLIENT_H_
#define _CLIENT_H_

#define SERVERADDR "63.32.125.183"
#define PORT 8081

void handle_login_admin(int sockfd, char **cookies, int *cookies_count);
void handle_add_user(int sockfd);
void handle_get_users(int sockfd);
void handle_delete_user(int sockfd);
void handle_logout_admin(int sockfd);
void handle_login(int sockfd);
void handle_get_access(int sockfd);
void handle_logout(int sockfd);
char *send_jwt_request(const char *method, const char *url, const char *payload);
void handle_get_movies(int sockfd);
void handle_get_movie(int sockfd);
void handle_add_movie(int sockfd);
void handle_update_movie(int sockfd);
void handle_delete_movie(int sockfd);
void handle_get_collections(int sockfd);
void handle_get_collection(int sockfd);
void handle_add_collection(int sockfd);
void handle_add_movie_to_collection(int sockfd);
void handle_delete_collection(int sockfd);
void handle_delete_movie_from_collection(int sockfd);
void handle_exit(int sockfd);

#endif
