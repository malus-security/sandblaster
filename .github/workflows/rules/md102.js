const http_keywords = [
    "GET",
    "POST",
    "PUT",
    "PATCH",
    "DELETE",
    "Content-Type",
    "Content-Encoding",
    "User-Agent",
    "200 OK",
    "401 Unauthorized",
    "403 Forbidden",
    "API_DATA_READ",
    "API_DATA_WRITE",
    "API_META_READ",
    "API_META_WRITE",
    "USER",
    "EDITOR",
    "ENTITY_GROUP_ADMIN",
    "ADMIN"
];
const keywordsRegex = new RegExp(http_keywords.map(word => "\\b" + word + "\\b").join("|"));

const { InlineTokenChildren } = require("./common/inlineTokenChildren");

module.exports = {
    names: ["MD102", "backtick-http"],
    description: "HTTP keywords must be fenced.",
    tags: ["backtick", "HTTP", "HTTPS"],
    "function": (params, onError) => {
        var inHeading = false;
        for (let token of params.tokens) {
            switch (token.type) {
                case "heading_open":
                    inHeading = true; break;
                case "heading_close":
                    inHeading = false; break;
                case "inline":
                    if (!inHeading) {
                        let children = new InlineTokenChildren(token);
                        for (let { token: child, column, lineNumber } of children) {
                            if (child.type === "text") {
                                let exactCaseMatch = child.content.match(keywordsRegex);
                                if (exactCaseMatch != null) {
                                    let match = exactCaseMatch[0];
                                    onError({
                                        lineNumber,
                                        detail: `Expected \`${match}\`. Actual ${match}.`,
                                        range: [column + exactCaseMatch.index, match.length]
                                    })
                                }
                            }
                        }
                    }
            }
        }
    }
};
