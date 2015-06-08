#ifndef CONFIG_PARSER_H_
#define CONFIG_PARSER_H_

typedef enum config_parser_rc_e {
    CONFIG_PARSER_OK,
    CONFIG_PARSER_ERROR
} config_parser_rc_t;

config_parser_rc_t config_parse(char *config_file);

#endif
