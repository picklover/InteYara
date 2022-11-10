#include <windows.h>
#include <stdlib.h>
#include "helper.h"
#include "yara.h"

#define SCAN_PROCESS

int yaraCallback_function(
    YR_SCAN_CONTEXT* context,
    int message,
    void* message_data,
    void* user_data)
{
    if (message == CALLBACK_MSG_RULE_MATCHING)
    {
        printf("MyPassed user data is:%s\n", (char*)user_data); // hello
        YR_RULE* rules = (YR_RULE*)message_data;
        YR_STRING* string = NULL;
        YR_MATCH* match = NULL;
        yr_rule_strings_foreach(rules, string)
        {
            yr_string_matches_foreach(context, string, match)
            {
                printf("Matches[%s] \"%s\" offset: %02llx\n", string->identifier, (char*)string->string, match->offset);
            }
        }
    }
    return CALLBACK_CONTINUE;
};

void testYaraScan()
{
    yr_initialize();
    YR_COMPILER* compiler;
    yr_compiler_create(&compiler);
    FILE* fp = fopen("mysig.yara", "r");
    yr_compiler_add_file(compiler, fp, NULL, NULL);

    YR_RULES* rules;
    yr_compiler_get_rules(compiler, &rules);
    const char* myuserdata_pass = "hello";

#ifdef SCAN_PROCESS
    int target_pid = getPid("notepad.exe");
    yr_rules_scan_proc(rules, target_pid, SCAN_FLAGS_FAST_MODE, yaraCallback_function, (void*)myuserdata_pass, NULL);
#else
    yr_rules_scan_file(rules, "notepad.exe", SCAN_FLAGS_FAST_MODE, yaraCallback_function, (void*)myuserdata_pass, NULL);
#endif
    
    yr_rules_destroy(rules);
    yr_compiler_destroy(compiler);

    yr_finalize();
}

int main()
{   
    testYaraScan();
    return 0;
}

