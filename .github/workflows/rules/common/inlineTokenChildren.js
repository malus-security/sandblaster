 class InlineTokenChildren {
    constructor(token) {
        if (token.type === "inline") {
            this.root = token;
            this.column = -1;
            this.lineNumber = token.map[0];
        } else {
            throw new TypeError("wrong argument token type");
        }
    }

    *[Symbol.iterator]() {
        for (let token of this.root.children) {
            let { line, lineNumber } = token;
            if (this.lineNumber !== lineNumber) {
                this.column = -1;
                this.lineNumber = lineNumber;
            }
            this.column = line.indexOf(token.content, this.column + 1);
            yield { token, column: this.column + 1, lineNumber };
        }
    }
}

module.exports = { InlineTokenChildren };
