"use strict";

module.exports = {
  names: ["MD104", "one line per sentence"],
  description: "one line (and only one line) per sentence",
  tags: ["sentences"],
  function: function rule(params, onError) {
    for (const inline of params.tokens.filter(function filterToken(token) {
      return token.type === "inline";
    })) {
      var actual_lines = inline.content.split("\n");
      actual_lines.forEach((line, index, arr) => {
		let outside = true;
		let count = 0;
		Array.from(line).forEach((char) => {
			if ((char == "." || char == "?" || char == "!" || char == ";" || char == ":") && outside) {
				count++;
			}
			if (char == "`") outside = !outside;
			if (char == "[") outside = false;
			if (char == "(") outside = false;
			if (char == "]") outside = true;
			if (char == ")") outside = true;
		});
        if (count > 1) {
          onError({
            lineNumber: inline.lineNumber + index,
            detail:
              "Expected one sentence per line. Multiple end of sentence punctuation signs found on one line!",
          });
        }
      });
    }
  },
};
