#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include "parson.h"
#include "helpers.h"
#include "requests.h"
#include "client.h"

char jwt_token[1024];
char session_cookie[256] = "";

void handle_login_admin(int sockfd, char **cookies, int *cookies_count) {
    char username[102], password[102];
    printf("username=");
    scanf("%s", username);
    getchar();
    printf("password=");
    scanf("%s", password);
    getchar();

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char *json_string = json_serialize_to_string(root_value);

    char *message = compute_post_request(SERVERADDR, "/api/v1/tema/admin/login", "application/json", &json_string, 1, NULL, 0);
    send_to_server(sockfd, message);
    free(message);
    char *response = receive_from_server(sockfd);

    if (strstr(response, "401 UNAUTHORIZED")) {
        printf("ERROR: Autentificare esuata\n");
        return;
    } else if (strstr(response, "403 FORBIDDEN")) {
        printf("ERROR: Lipsă permisiuni admin.\n");
        return;
    } else if (strstr(response, "200 OK")) {
        printf("SUCCESS: Admin autentificat cu succes\n");

        char *cookie_start = strstr(response, "Set-Cookie: ");
        if (cookie_start) {
            cookie_start += strlen("Set-Cookie: ");
            char *cookie_end = strstr(cookie_start, ";");
            if (cookie_end) {
                size_t cookie_len = cookie_end - cookie_start;
                strncpy(session_cookie, cookie_start, cookie_len);
                session_cookie[cookie_len] = '\0';
            }
        }
    } else {
        printf("ERROR: Autentificare esuata\n");
    }

    json_free_serialized_string(json_string);
    json_value_free(root_value);
    free(response);
}

void handle_add_user(int sockfd) {
    char username[1024], password[1024];
    printf("username=");
    scanf("%s", username);
    getchar();
    printf("password=");
    scanf("%s", password);
    getchar();

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char *json_string = json_serialize_to_string(root_value);

    char *message = compute_post_request(SERVERADDR, "/api/v1/tema/admin/users", "application/json", &json_string, 1, session_cookie[0] ? (char*[]){session_cookie} : NULL, session_cookie[0] ? 1 : 0);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    if (strstr(response, "201 CREATED")) {
        printf("SUCCESS: Utilizator adaugat cu succes\n");
    } else {
        printf("ERROR: Adaugare utilizator esuata\n");
    }

    json_free_serialized_string(json_string);
    json_value_free(root_value);
    free(message);
    free(response);
}

void handle_get_users(int sockfd) {
    char *cookies[1] = { session_cookie };
    char *message = compute_get_request(
        SERVERADDR,
        "/api/v1/tema/admin/users",
        NULL,
        session_cookie[0] ? cookies : NULL,
        session_cookie[0] ? 1 : 0
    );
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);

    if (strstr(response, "403 FORBIDDEN")) {
        printf("ERROR: Lipsă permisiuni admin.\n");
        return;
    } else if (strstr(response, "401 UNAUTHORIZED")) {
        printf("ERROR: Lipsă permisiuni admin.\n");
        return;
    } else if (strstr(response, "200 OK")) {
        JSON_Value *root_value = json_parse_string(basic_extract_json_response(response));
        if (root_value == NULL) {
            printf("ERROR: Invalid JSON response.\n");
        } else {
            JSON_Object *root_object = json_value_get_object(root_value);
            JSON_Array *users = json_object_get_array(root_object, "users");
            size_t users_count = json_array_get_count(users);

            printf("SUCCESS: Lista utilizatorilor\n");
            for (size_t i = 0; i < users_count; i++) {
                JSON_Object *user = json_array_get_object(users, i);
                printf("#%d %s:%s\n",
                       (int)json_object_get_number(user, "id"),
                       json_object_get_string(user, "username"),
                       json_object_get_string(user, "password"));
            }
            json_value_free(root_value);
        }
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    free(message);
    free(response);
}

void handle_delete_user(int sockfd) {
    char username[1024];
    printf("username=");
    fgets(username, LINELEN, stdin);
    username[strcspn(username, "\n")] = 0;

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "username", username);

    char *json_string = json_serialize_to_string(root_value);
    char url[LINELEN];
    sprintf(url, "/api/v1/tema/admin/users/%s", username);
    char *message = compute_post_request(SERVERADDR, url, "application/json", &json_string, 1, session_cookie[0] ? (char*[]){session_cookie} : NULL, session_cookie[0] ? 1 : 0);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);

    if (strstr(response, "400 Bad Request")) {
        printf("ERROR: Cerere eșuată.\n");
    } else {
        printf("%s\n", response);
    }

    json_free_serialized_string(json_string);
    json_value_free(root_value);
    free(message);
    free(response);
}

void handle_logout_admin(int sockfd) {
    char *message = compute_get_request(SERVERADDR, "/api/v1/tema/admin/logout", NULL, session_cookie[0] ? (char*[]){session_cookie} : NULL, session_cookie[0] ? 1 : 0);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);
    if (strstr(response, "401 Unauthorized") || strstr(response, "401 UNAUTHORIZED")) {
        printf("ERROR: Logout esuat\n");
        session_cookie[0] = '\0';
    } else {
        printf("SUCCESS: Logout realizat cu succes\n");
        session_cookie[0] = '\0';
    }
    free(message);
    free(response);
}

void handle_login(int sockfd) {
    char admin_username[1024], username[1024], password[1024];
    printf("admin_username=");
    scanf("%s", admin_username);
    getchar();
    printf("username=");
    scanf("%s", username);
    getchar();
    printf("password=");
    scanf("%s", password);
    getchar();

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "admin_username", admin_username);
    json_object_set_string(root_object, "username", username);
    json_object_set_string(root_object, "password", password);
    char *json_string = json_serialize_to_string(root_value);

    char *message = compute_post_request(SERVERADDR, "/api/v1/tema/user/login", "application/json", &json_string, 1, session_cookie[0] ? (char*[]){session_cookie} : NULL, session_cookie[0] ? 1 : 0);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);

    if (strstr(response, "200 OK")) {
        printf("SUCCESS: Autentificare reușită\n");
        char *cookie_start = strstr(response, "Set-Cookie: ");
        if (cookie_start) {
            cookie_start += strlen("Set-Cookie: ");
            char *cookie_end = strstr(cookie_start, ";");
            if (cookie_end) {
                size_t cookie_len = cookie_end - cookie_start;
                strncpy(session_cookie, cookie_start, cookie_len);
                session_cookie[cookie_len] = '\0';
            }
        }
    } else if (strstr(response, "401 UNAUTHORIZED")) {
        printf("ERROR: Credențialele nu se potrivesc sau reautentificare necesară.\n");
    } else {
        printf("ERROR: Autentificare eșuată\n");
    }

    json_free_serialized_string(json_string);
    json_value_free(root_value);
    free(message);
    free(response);
}

void handle_get_access(int sockfd) {
    char *message = compute_get_request(SERVERADDR, "/api/v1/tema/library/access", "application/json", session_cookie[0] ? (char*[]){session_cookie} : NULL, session_cookie[0] ? 1 : 0);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);

    if (strstr(response, "401 UNAUTHORIZED")) {
        printf("ERROR: Neautentificat. Trebuie să demonstraţi că sunteţi autentificaţi!\n");
    } else if (strstr(response, "200 OK")) {
        const char *json_str = basic_extract_json_response(response);
        JSON_Value *root_value = json_parse_string(json_str);
        JSON_Object *root_object = json_value_get_object(root_value);
        const char *token = json_object_get_string(root_object, "token");
        if (token) {
            strncpy(jwt_token, token, sizeof(jwt_token) - 1);
            jwt_token[sizeof(jwt_token) - 1] = '\0';
            printf("SUCCESS: Token JWT primit\n");
        } else {
            printf("ERROR: Token JWT lipsă în răspuns.\n");
        }
        json_value_free(root_value);
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    free(message);
    free(response);
}

void handle_logout(int sockfd) {
    char *message = compute_get_request(SERVERADDR, "/api/v1/tema/user/logout", "application/json", session_cookie[0] ? (char*[]){session_cookie} : NULL, session_cookie[0] ? 1 : 0);
    send_to_server(sockfd, message);
    char *response = receive_from_server(sockfd);

    if (strstr(response, "200 OK") || strstr(response, "204 No Content")) {
        printf("SUCCESS: Utilizator delogat\n");
        session_cookie[0] = '\0';
    } else if (strstr(response, "401 Unauthorized") || strstr(response, "401 UNAUTHORIZED") || strstr(response, "403 Forbidden")) {
        printf("ERROR: Neautentificat.\n");
        session_cookie[0] = '\0';
    } else {
        printf("SUCCESS: Utilizator delogat\n");
        session_cookie[0] = '\0';
    }

    free(message);
    free(response);
}

char *send_jwt_request(const char *method, const char *url, const char *payload) {

    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) return NULL;

    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);
    inet_aton(SERVERADDR, &serv_addr.sin_addr);

    if (connect(sockfd, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        close(sockfd);
        return NULL;
    }

    char req[BUFLEN], cookie[300] = "", auth[1200] = "";
    if (session_cookie[0]) {
        snprintf(cookie, sizeof(cookie), "Cookie: %s\r\n", session_cookie);
    }
    if (jwt_token[0]) {
        snprintf(auth, sizeof(auth), "Authorization: Bearer %s\r\n", jwt_token);
    }

    snprintf(req, sizeof(req),
        "%s %s HTTP/1.1\r\n"
        "Host: %s\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: %ld\r\n"
        "%s%s"
        "Connection: close\r\n\r\n"
        "%s",
        method, url, SERVERADDR,
        payload ? strlen(payload) : 0,
        cookie, auth,
        payload ? payload : "");

    send(sockfd, req, strlen(req), 0);

    char *response = calloc(1, 1);
    char buf[BUFLEN];
    int n;
    while ((n = recv(sockfd, buf, sizeof(buf) - 1, 0)) > 0) {
        buf[n] = '\0';
        size_t len = strlen(response);
        response = realloc(response, len + n + 1);
        strcpy(response + len, buf);
    }
    close(sockfd);
    return response;
}

void handle_get_movies(int sockfd) {
    if (session_cookie[0] == '\0') {
        printf("ERROR: \n");
        return;
    }

    char *response = send_jwt_request("GET", "/api/v1/tema/library/movies", NULL);

    if (!response) {
        printf("ERROR: Cerere eșuată.\n");
        return;
    }

    if (strstr(response, "403 Forbidden")) {
        printf("ERROR: Fără acces library.\n");
    } else if (strstr(response, "401 Unauthorized")) {
        printf("ERROR: Neautentificat.\n");
    } else if (strstr(response, "200 OK")) {
        JSON_Value *root_value = json_parse_string(basic_extract_json_response(response));
        if (root_value == NULL) {
            printf("ERROR: Invalid JSON response.\n");
        } else {
            JSON_Array *movies = NULL;
            if (json_value_get_type(root_value) == JSONArray) {
                movies = json_value_get_array(root_value);
            } else if (json_value_get_type(root_value) == JSONObject) {
                JSON_Object *obj = json_value_get_object(root_value);
                movies = json_object_get_array(obj, "movies");
            }
            if (!movies) {
                printf("ERROR: Invalid movies format.\n");
            } else {
                size_t movies_count = json_array_get_count(movies);
                printf("SUCCESS: Lista filmelor\n");
                for (size_t i = 0; i < movies_count; i++) {
                    JSON_Object *movie = json_array_get_object(movies, i);
                    printf("#%d %s\n",
                        (int)json_object_get_number(movie, "id"),
                        json_object_get_string(movie, "title"));
                }
            }
            json_value_free(root_value);
        }
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    free(response);
}

void handle_get_movie(int sockfd) {
    if (session_cookie[0] == '\0') {
        printf("ERROR: Fără acces library.\n");
        return;
    }
    char id_str[32];
    printf("id=");
    fgets(id_str, sizeof(id_str), stdin);
    id_str[strcspn(id_str, "\n")] = 0;
    int id = atoi(id_str);
    if (id <= 0) {
        printf("ERROR: ID invalid.\n");
        return;
    }
    char url[LINELEN];
    snprintf(url, sizeof(url), "/api/v1/tema/library/movies/%d", id);

    char *response = send_jwt_request("GET", url, NULL);

    if (!response) {
        printf("ERROR: Cerere eșuată.\n");
        return;
    }

    if (strstr(response, "403 Forbidden")) {
        printf("ERROR: Fără acces library.\n");
    } else if (strstr(response, "404 Not Found")) {
        printf("ERROR: ID invalid.\n");
    } else if (strstr(response, "401 Unauthorized")) {
        printf("ERROR: Neautentificat.\n");
    } else if (strstr(response, "200 OK")) {
        const char *body = strstr(response, "\r\n\r\n");
        if (!body) {
            puts("ERROR:");
            free(response);
            return;
        }
        body += 4;

        JSON_Value *root_value = json_parse_string(body);
        if (!root_value) {
            puts("ERROR:");
            free(response);
            return;
        }

        JSON_Object *obj = json_value_get_object(root_value);
        if (!obj) {
            puts("ERROR:");
            json_value_free(root_value);
            free(response);
            return;
        }

        const char *title = json_object_get_string(obj, "title");
        int year = (int)json_object_get_number(obj, "year");
        const char *description = json_object_get_string(obj, "description");
        double rating = 0.0;
        if (json_object_get_value(obj, "rating") != NULL) {
            if (json_value_get_type(json_object_get_value(obj, "rating")) == JSONString) {
                const char *rating_str = json_object_get_string(obj, "rating");
                if (rating_str) {
                    rating = atof(rating_str);
                }
            } else {
                rating = json_object_get_number(obj, "rating");
            }
        }
        printf("SUCCESS: Detalii film:\n");
        printf("Title: %s\n", title);
        printf("Year: %d\n", year);
        printf("Rating: %.1f\n", rating);
        printf("Description: %s\n", description ? description : "(none)");
        json_value_free(root_value);
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    free(response);
}


void handle_add_movie(int sockfd) {
    char title[256], description[512], year_str[32], rating_str[32];
    int year;
    double rating;

    printf("title=");
    fgets(title, sizeof(title), stdin);
    title[strcspn(title, "\n")] = 0;

    printf("year=");
    fgets(year_str, sizeof(year_str), stdin);
    year_str[strcspn(year_str, "\n")] = 0;
    year = atoi(year_str);

    printf("description=");
    fgets(description, sizeof(description), stdin);
    description[strcspn(description, "\n")] = 0;

    printf("rating=");
    fgets(rating_str, sizeof(rating_str), stdin);
    rating_str[strcspn(rating_str, "\n")] = 0;
    rating = atof(rating_str);

    if (jwt_token[0] == '\0') {
        printf("ERROR: Fără acces library.\n");
        return;
    }

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_string(root_object, "title", title);
    json_object_set_number(root_object, "year", year);
    json_object_set_string(root_object, "description", description);
    json_object_set_number(root_object, "rating", rating);
    char *json_string = json_serialize_to_string(root_value);

    char *response = send_jwt_request("POST", "/api/v1/tema/library/movies", json_string);

    if (strstr(response, "403 Forbidden")) {
        printf("ERROR: Fără acces library.\n");
    } else if (strstr(response, "400 Bad Request")) {
        printf("ERROR: Date invalide/incomplete.\n");
    } else if (strstr(response, "201 CREATED") || strstr(response, "200 OK")) {
        printf("SUCCESS: Film adăugat\n");
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    json_free_serialized_string(json_string);
    json_value_free(root_value);
    free(response);
}

void handle_update_movie(int sockfd) {
    if(session_cookie[0] == '\0') {
        printf("ERROR:\n");
        return;
    }
    char id_str[20], title[256], year_str[32], description[512], rating_str[10];
    printf("id=");
    fgets(id_str, sizeof(id_str), stdin);
    id_str[strcspn(id_str, "\n")] = 0;
    int id = atoi(id_str);
    if (id <= 0) {
        printf("ERROR: ID invalid.\n");
        return;
    }

    printf("title=");
    fgets(title, sizeof(title), stdin);
    title[strcspn(title, "\n")] = '\0';

    printf("year=");
    fgets(year_str, sizeof(year_str), stdin);
    year_str[strcspn(year_str, "\n")] = 0;

    printf("description=");
    fgets(description, sizeof(description), stdin);
    description[strcspn(description, "\n")] = 0;

    printf("rating=");
    fgets(rating_str, sizeof(rating_str), stdin);
    rating_str[strcspn(rating_str, "\n")] = '\0';

    int year = atoi(year_str);
    double rating = atof(rating_str);

    if (jwt_token[0] == '\0') {
        printf("ERROR: Fără acces library.\n");
        return;
    }

    char url[LINELEN];
    snprintf(url, sizeof(url), "/api/v1/tema/library/movies/%d", id);

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);

    if (strlen(title) > 0)
        json_object_set_string(root_object, "title", title);
    if (year > 0)
        json_object_set_number(root_object, "year", year);
    if (strlen(description) > 0)
        json_object_set_string(root_object, "description", description);
    if (rating > 0)
        json_object_set_number(root_object, "rating", rating);

    char *json_string = json_serialize_to_string(root_value);

    char *response = send_jwt_request("PUT", url, json_string);

    if (!response) {
        printf("ERROR: Cerere eșuată.\n");
        json_free_serialized_string(json_string);
        json_value_free(root_value);
        return;
    }

    if (strstr(response, "403 Forbidden")) {
        printf("ERROR: Fără acces library.\n");
    } else if (strstr(response, "404 Not Found")) {
        printf("ERROR: ID invalid.\n");
    } else if (strstr(response, "400 Bad Request")) {
        printf("ERROR: Date invalide/incomplete.\n");
    } else if (strstr(response, "200 OK") || strstr(response, "204 No Content")) {
        printf("SUCCESS: Film actualizat\n");
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    json_free_serialized_string(json_string);
    json_value_free(root_value);
    free(response);
}

void handle_delete_movie(int sockfd) {
    if (session_cookie[0] == '\0') {
        printf("ERROR: Fără acces library.\n");
        return;
    }
    char id_str[32];
    printf("id=");
    fgets(id_str, sizeof(id_str), stdin);
    id_str[strcspn(id_str, "\n")] = 0;
    int id = atoi(id_str);
    if (id <= 0) {
        printf("ERROR: ID invalid.\n");
        return;
    }
    char url[LINELEN];
    snprintf(url, sizeof(url), "/api/v1/tema/library/movies/%d", id);

    char *response = send_jwt_request("DELETE", url, NULL);

    if (!response) {
        printf("ERROR: Cerere eșuată.\n");
        return;
    }

    if (strstr(response, "403 Forbidden")) {
        printf("ERROR: Fără acces library.\n");
    } else if (strstr(response, "404 Not Found")) {
        printf("ERROR: ID invalid.\n");
    } else if (strstr(response, "401 Unauthorized")) {
        printf("ERROR: Neautentificat.\n");
    } else if (strstr(response, "200 OK") || strstr(response, "204 No Content")) {
        printf("SUCCESS: Film șters cu succes\n");
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    free(response);
}

void handle_get_collections(int sockfd) {
    if (session_cookie[0] == '\0') {
        printf("ERROR: Fără acces library.\n");
        return;
    }

    char *response = send_jwt_request("GET", "/api/v1/tema/library/collections", NULL);

    if (!response) {
        printf("ERROR: Cerere eșuată.\n");
        return;
    }

    if (strstr(response, "403 Forbidden")) {
        printf("ERROR: Fără acces library.\n");
    } else if (strstr(response, "401 Unauthorized")) {
        printf("ERROR: Neautentificat.\n");
    } else if (strstr(response, "200 OK")) {
        JSON_Value *root_value = json_parse_string(basic_extract_json_response(response));
        if (!root_value) {
            printf("ERROR: Invalid JSON response.\n");
        } else {
            JSON_Array *collections = NULL;
            if (json_value_get_type(root_value) == JSONArray) {
                collections = json_value_get_array(root_value);
            } else if (json_value_get_type(root_value) == JSONObject) {
                JSON_Object *obj = json_value_get_object(root_value);
                collections = json_object_get_array(obj, "collections");
            }
            if (!collections) {
                printf("ERROR: Invalid collections format.\n");
            } else {
                size_t count = json_array_get_count(collections);
                printf("SUCCESS: Lista colecțiilor\n");
                for (size_t i = 0; i < count; i++) {
                    JSON_Object *coll = json_array_get_object(collections, i);
                    int id = (int)json_object_get_number(coll, "id");
                    const char *title = json_object_get_string(coll, "title");
                    printf("#%d: %s\n", id, title ? title : "(no title)");
                }
            }
            json_value_free(root_value);
        }
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    free(response);
}

void handle_get_collection(int sockfd) {
    if (jwt_token[0] == '\0') {
        printf("ERROR: Fără acces library.\n");
        return;
    }
    char id_str[32];
    printf("id=");
    fgets(id_str, sizeof(id_str), stdin);
    id_str[strcspn(id_str, "\n")] = 0;
    int id = atoi(id_str);
    if (id <= 0) {
        printf("ERROR: ID invalid.\n");
        return;
    }
    char url[LINELEN];
    snprintf(url, sizeof(url), "/api/v1/tema/library/collections/%d", id);

    char *response = send_jwt_request("GET", url, NULL);

    if (!response) {
        printf("ERROR: Cerere eșuată.\n");
        return;
    }

    if (strstr(response, "403 Forbidden")) {
        printf("ERROR: Fără acces library.\n");
    } else if (strstr(response, "404 Not Found")) {
        printf("ERROR: ID invalid.\n");
    } else if (strstr(response, "401 Unauthorized")) {
        printf("ERROR: Neautentificat.\n");
    } else if (strstr(response, "200 OK")) {
        const char *body = strstr(response, "\r\n\r\n");
        if (!body) {
            puts("ERROR:");
            free(response);
            return;
        }
        body += 4;

        JSON_Value *root_value = json_parse_string(body);
        if (!root_value) {
            puts("ERROR:");
            free(response);
            return;
        }

        JSON_Object *obj = json_value_get_object(root_value);
        if (!obj) {
            puts("ERROR:");
            json_value_free(root_value);
            free(response);
            return;
        }

        const char *title = json_object_get_string(obj, "title");
        const char *owner = json_object_get_string(obj, "owner");
        JSON_Array *movies = json_object_get_array(obj, "movies");

        printf("SUCCESS: Detalii colectie\n");
        printf("title: %s\n", title ? title : "(no title)");
        printf("owner: %s\n", owner ? owner : "(no owner)");

        if (movies && json_array_get_count(movies) > 0) {
            for (size_t i = 0; i < json_array_get_count(movies); i++) {
                JSON_Object *movie = json_array_get_object(movies, i);
                if (!movie) continue;
                int movie_id = (int)json_object_get_number(movie, "id");
                const char *movie_title = json_object_get_string(movie, "title");
                printf("#%d: %s\n", movie_id, movie_title ? movie_title : "(no title)");
            }
        } else {
            printf("(Nicio filma in colectie)\n");
        }

        json_value_free(root_value);
        free(response);
        return;
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    free(response);
}

void handle_add_collection(int sockfd) {
    if (jwt_token[0] == '\0') {
        puts("ERROR:");
        return;
    }

    char title[256], num_movies_str[16];
    printf("title=");
    fgets(title, sizeof(title), stdin);
    title[strcspn(title, "\n")] = 0;
    printf("num_movies=");
    fgets(num_movies_str, sizeof(num_movies_str), stdin);
    int num_movies = atoi(num_movies_str);

    if (num_movies <= 0) {
        puts("ERROR:");
        return;
    }

    int movie_ids[100];
    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    JSON_Value *movies_array_val = json_value_init_array();
    JSON_Array *movies_array = json_value_get_array(movies_array_val);

    for (int i = 0; i < num_movies; i++) {
        char prompt[32], id_str[20];
        snprintf(prompt, sizeof(prompt), "movie_id[%d]=", i);
        printf("%s", prompt);
        fgets(id_str, sizeof(id_str), stdin);
        id_str[strcspn(id_str, "\n")] = 0;
        int movie_id = atoi(id_str);
        if (movie_id <= 0) {
            puts("ERROR:");
            json_value_free(movies_array_val);
            json_value_free(root_value);
            return;
        }
        movie_ids[i] = movie_id;
        json_array_append_number(movies_array, movie_id);
    }

    json_object_set_string(root_object, "title", title);
    json_object_set_value(root_object, "movie_ids", movies_array_val);

    char *payload = json_serialize_to_string(root_value);
    char *resp = send_jwt_request("POST", "/api/v1/tema/library/collections", payload);

    int code = 0;
    if (resp) {
        char *status = strstr(resp, "HTTP/");
        if (status) {
            int major, minor;
            sscanf(status, "HTTP/%d.%d %d", &major, &minor, &code);
        }
    }

    if (code == 200 || code == 201) {
        puts("SUCCESS: Colectie adaugata");

        const char *body = strstr(resp, "\r\n\r\n");
        if (body) {
            body += 4;
            JSON_Value *resp_val = json_parse_string(body);
            if (resp_val) {
                JSON_Object *resp_obj = json_value_get_object(resp_val);
                int collection_id = (int)json_object_get_number(resp_obj, "id");

                for (int i = 0; i < num_movies; i++) {
                    JSON_Value *add_val = json_value_init_object();
                    JSON_Object *add_obj = json_value_get_object(add_val);
                    json_object_set_number(add_obj, "id", movie_ids[i]);
                    char *add_payload = json_serialize_to_string(add_val);

                    char url[256];
                    snprintf(url, sizeof(url), "/api/v1/tema/library/collections/%d/movies", collection_id);

                    char *add_resp = send_jwt_request("POST", url, add_payload);
                    int add_code = 0;
                    if (add_resp) {
                        char *add_status = strstr(add_resp, "HTTP/");
                        if (add_status) {
                            int major, minor;
                            sscanf(add_status, "HTTP/%d.%d %d", &major, &minor, &add_code);
                        }
                    }

                    if (add_code == 200 || add_code == 201 || add_code == 204) {
                        printf("SUCCESS: Film #%d adaugat in colectie\n", movie_ids[i]);
                    } else {
                        printf("ERROR:");
                    }

                    json_free_serialized_string(add_payload);
                    json_value_free(add_val);
                    free(add_resp);
                }

                json_value_free(resp_val);
            }
        }
    } else {
        printf("ERROR:");
    }

    json_free_serialized_string(payload);
    json_value_free(root_value);
    free(resp);
}

void handle_add_movie_to_collection(int sockfd) {
    if (session_cookie[0] == '\0') {
        printf("ERROR: Fără acces library.\n");
        return;
    }

    char collection_id_str[32], movie_id_str[32];
    printf("collection_id=");
    fgets(collection_id_str, sizeof(collection_id_str), stdin);
    collection_id_str[strcspn(collection_id_str, "\n")] = 0;
    int collection_id = atoi(collection_id_str);
    if (collection_id <= 0) {
        printf("ERROR: Date invalide/incomplete.\n");
        return;
    }

    printf("movie_id=");
    fgets(movie_id_str, sizeof(movie_id_str), stdin);
    movie_id_str[strcspn(movie_id_str, "\n")] = 0;
    int movie_id = atoi(movie_id_str);
    if (movie_id <= 0) {
        printf("ERROR: Date invalide/incomplete.\n");
        return;
    }

    char url[LINELEN];
    snprintf(url, sizeof(url), "/api/v1/tema/library/collections/%d/movies", collection_id);

    JSON_Value *root_value = json_value_init_object();
    JSON_Object *root_object = json_value_get_object(root_value);
    json_object_set_number(root_object, "id", movie_id);
    char *json_string = json_serialize_to_string(root_value);

    char *response = send_jwt_request("POST", url, json_string);

    if (!response) {
        printf("ERROR: Cerere eșuată.\n");
        json_free_serialized_string(json_string);
        json_value_free(root_value);
        return;
    }

    if (strstr(response, "403 Forbidden")) {
        printf("ERROR: Fără acces library sau nu sunteți owner.\n");
    } else if (strstr(response, "400 Bad Request")) {
        printf("ERROR: Date invalide/incomplete.\n");
    } else if (strstr(response, "201 CREATED") || strstr(response, "200 OK")) {
        printf("SUCCESS: Film adăugat în colecție\n");
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    json_free_serialized_string(json_string);
    json_value_free(root_value);
    free(response);
}

void handle_delete_collection(int sockfd) {
    if (session_cookie[0] == '\0') {
        printf("ERROR: Fără acces library.\n");
        return;
    }

    char id_str[32];
    printf("id=");
    fgets(id_str, sizeof(id_str), stdin);
    id_str[strcspn(id_str, "\n")] = 0;
    int id = atoi(id_str);
    if (id <= 0) {
        printf("ERROR: ID invalid.\n");
        return;
    }

    char url[LINELEN];
    snprintf(url, sizeof(url), "/api/v1/tema/library/collections/%d", id);

    char *response = send_jwt_request("DELETE", url, NULL);

    if (!response) {
        printf("ERROR: Cerere eșuată.\n");
        return;
    }

    if (strstr(response, "403 Forbidden")) {
        printf("ERROR: Fără acces library sau nu sunteți owner.\n");
    } else if (strstr(response, "404 Not Found")) {
        printf("ERROR: ID invalid.\n");
    } else if (strstr(response, "401 Unauthorized")) {
        printf("ERROR: Neautentificat.\n");
    } else if (strstr(response, "200 OK") || strstr(response, "204 No Content")) {
        printf("SUCCESS: Colecție ștearsă\n");
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    free(response);
}

void handle_delete_movie_from_collection(int sockfd) {
    if (session_cookie[0] == '\0') {
        printf("ERROR: Fără acces library.\n");
        return;
    }

    char collection_id_str[32], movie_id_str[32];
    printf("collection_id=");
    fgets(collection_id_str, sizeof(collection_id_str), stdin);
    collection_id_str[strcspn(collection_id_str, "\n")] = 0;
    int collection_id = atoi(collection_id_str);
    if (collection_id <= 0) {
        printf("ERROR: ID invalid.\n");
        return;
    }

    printf("movie_id=");
    fgets(movie_id_str, sizeof(movie_id_str), stdin);
    movie_id_str[strcspn(movie_id_str, "\n")] = 0;
    int movie_id = atoi(movie_id_str);
    if (movie_id <= 0) {
        printf("ERROR: ID invalid.\n");
        return;
    }

    char url[LINELEN];
    snprintf(url, sizeof(url), "/api/v1/tema/library/collections/%d/movies/%d", collection_id, movie_id);

    char *response = send_jwt_request("DELETE", url, NULL);

    if (!response) {
        printf("ERROR: Cerere eșuată.\n");
        return;
    }

    if (strstr(response, "403 Forbidden")) {
        printf("ERROR: Fără acces library sau nu sunteți owner.\n");
    } else if (strstr(response, "401 Unauthorized")) {
        printf("ERROR: Neautentificat.\n");
    } else if (strstr(response, "200 OK") || strstr(response, "204 No Content") || strstr(response, "404 Not Found")) {
        printf("SUCCESS: Film șters din colecție\n");
    } else {
        printf("ERROR: Cerere eșuată.\n");
    }

    free(response);
}

void handle_exit(int sockfd) {
    close_connection(sockfd);
    jwt_token[0] = '\0';
    session_cookie[0] = '\0';
    exit(0);
}

int main(int argc, char *argv[]) {
    char command[LINELEN];
    int sockfd = open_connection(SERVERADDR, PORT, AF_INET, SOCK_STREAM, 0);

    while (1) {
        fgets(command, LINELEN, stdin);
        command[strcspn(command, "\n")] = 0;

        if (strcmp(command, "exit") == 0) {
            handle_exit(sockfd);
        } else if (strcmp(command, "login_admin") == 0) {
            handle_login_admin(sockfd, NULL, NULL);
        } else if (strcmp(command, "add_user") == 0) {
            handle_add_user(sockfd);
        } else if (strcmp(command, "get_users") == 0) {
            handle_get_users(sockfd);
        } else if (strcmp(command, "delete_user") == 0) {
            handle_delete_user(sockfd);
        } else if (strcmp(command, "logout_admin") == 0) {
            handle_logout_admin(sockfd);
        } else if (strcmp(command, "login") == 0) {
            handle_login(sockfd);
        } else if (strcmp(command, "get_access") == 0) {
            handle_get_access(sockfd);
        } else if (strcmp(command, "get_movies") == 0) {
            handle_get_movies(sockfd);
        } else if (strcmp(command, "get_movie") == 0) {
            handle_get_movie(sockfd);
        } else if (strcmp(command, "logout") == 0) {
            handle_logout(sockfd);
        } else if (strcmp(command, "add_movie") == 0) {
            handle_add_movie(sockfd);
        } else if (strcmp(command, "update_movie") == 0) {
            handle_update_movie(sockfd);
        } else if (strcmp(command, "delete_movie") == 0) {
            handle_delete_movie(sockfd);
        } else if (strcmp(command, "get_collections") == 0) {
            handle_get_collections(sockfd);
        } else if (strcmp(command, "get_collection") == 0) {
            handle_get_collection(sockfd);
        } else if (strcmp(command, "add_collection") == 0) {
            handle_add_collection(sockfd);
        } else if (strcmp(command, "add_movie_to_collection") == 0) {
            handle_add_movie_to_collection(sockfd);
        } else if (strcmp(command, "delete_movie_from_collection") == 0) {
            handle_delete_movie_from_collection(sockfd);
        } else if (strcmp(command, "delete_collection") == 0) {
            handle_delete_collection(sockfd);
        } else {
            printf("Unknown command: %s\n", command);
        }
    }

    close_connection(sockfd);

    return 0;
}
