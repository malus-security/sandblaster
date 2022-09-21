class WordPattern {
    constructor(pattern, parameters) {
        const escapedDots = pattern.replace(/\\?\./g, "\\.");
        this.pattern = parameters && parameters.hasOwnProperty('noWordBoundary') ? escapedDots : "\\b" + escapedDots + "\\b";
        const modifiers = parameters && parameters.hasOwnProperty('caseSensitive') && parameters.caseSensitive ? "" : "i";
        this.regex = new RegExp(this.pattern, modifiers);
        this.suggestion = parameters && parameters.hasOwnProperty('suggestion') ? parameters.suggestion : pattern;
        this.stringRegex = new RegExp("^" + escapedDots + "$", modifiers); // To match "Category" column words in changelogs, see case-sensitive.js
        this.skipForUseCases = !!(parameters && parameters.hasOwnProperty('skipForUseCases'));
    }

    test(line) {
        return new Match(line.match(this.regex));
    }
}

class Match {
    constructor(match) {
        this.match = match;
    }

    range() {
        if (this.match) {
            let column = this.match.index + 1;
            let length = this.match[0].length;
            if (this.match[2]) {
                column += this.match[1].length;
                length -= this.match[1].length;
            }
            return [column, length];
        }
        return null;
    }

    toString() {
        return this.match ? this.match.toString() : "null";
    }
}

module.exports = { WordPattern };
