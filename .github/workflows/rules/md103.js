"use strict";

module.exports = {
  "names": [ "MD103", "inline triple backticks" ],
  "description": "inline triple backticks",
  "tags": [ "backticks" ],
  "function": function rule(params, onError) {
    for (const inline of params.tokens.filter(function filterToken(token) {
      return token.type === "inline";
    })) {
        const index = inline.content.toLowerCase().indexOf("```");
        if (index !== -1) {
          onError({
            "lineNumber": inline.lineNumber,
            "context": inline.content.substr(index - 1, 4),
            "detail": "Expected `. Actual ```"
          });
        }
      }
  }
};
