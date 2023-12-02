//
// Created by 32319 on 2023/11/25.
//

#include <string.h>
#include "tool.h"

void remove_line_break(char *str, size_t size)
{
    if(!str)
        return;
    for(size_t i = 0; i < size; i++)
    {
        if(str[i] == '\n')
            str[i] = '\0';
    }
}
