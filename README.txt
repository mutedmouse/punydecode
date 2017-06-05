Author: Andrew Quill
********************

About:
   This custom command uses built-in python International Domain Name decoding to display original language sets of xn-- encoded domains.

Usage:

   <search> | punydecode field=<field>
   <search> | punydecode field=<field> detection

Output will include <pundecoded> with your decoded punycode addresses
Output with detection option included will now display narrow mode unicode characters recognized in International Domain Name identified

Future:
    Full python3x rewrite or future binding to support wide mode unicode and emojis.

Support:
    Email support at team@spłunk.com during weekday 9-5 (US, East Coast)
    Github support at https://github.com/mutedmouse/punydecode
    Please submit issues and documentation for improvements.
