// generatedy by JSX compiler 0.9.10 (2013-02-22 10:18:33 +0900; e3a1f2a04656dbfd626086b3c68606d0c9697212)
var JSX = {};
(function (JSX) {
/**
 * copies the implementations from source interface to target
 */
function $__jsx_merge_interface(target, source) {
	for (var k in source.prototype)
		if (source.prototype.hasOwnProperty(k))
			target.prototype[k] = source.prototype[k];
}

/**
 * defers the initialization of the property
 */
function $__jsx_lazy_init(obj, prop, func) {
	function reset(obj, prop, value) {
		delete obj[prop];
		obj[prop] = value;
		return value;
	}

	Object.defineProperty(obj, prop, {
		get: function () {
			return reset(obj, prop, func());
		},
		set: function (v) {
			reset(obj, prop, v);
		},
		enumerable: true,
		configurable: true
	});
}

/**
 * sideeffect().a /= b
 */
function $__jsx_div_assign(obj, prop, divisor) {
	return obj[prop] = (obj[prop] / divisor) | 0;
}

/*
 * global functions, renamed to avoid conflict with local variable names
 */
var $__jsx_parseInt = parseInt;
var $__jsx_parseFloat = parseFloat;
var $__jsx_isNaN = isNaN;
var $__jsx_isFinite = isFinite;

var $__jsx_encodeURIComponent = encodeURIComponent;
var $__jsx_decodeURIComponent = decodeURIComponent;
var $__jsx_encodeURI = encodeURI;
var $__jsx_decodeURI = decodeURI;

var $__jsx_ObjectToString = Object.prototype.toString;
var $__jsx_ObjectHasOwnProperty = Object.prototype.hasOwnProperty;

/*
 * profiler object, initialized afterwards
 */
function $__jsx_profiler() {
}

/*
 * public interface to JSX code
 */
JSX.require = function (path) {
	var m = $__jsx_classMap[path];
	return m !== undefined ? m : null;
};

JSX.profilerIsRunning = function () {
	return $__jsx_profiler.getResults != null;
};

JSX.getProfileResults = function () {
	return ($__jsx_profiler.getResults || function () { return {}; })();
};

JSX.postProfileResults = function (url) {
	if ($__jsx_profiler.postResults == null)
		throw new Error("profiler has not been turned on");
	return $__jsx_profiler.postResults(url);
};

JSX.resetProfileResults = function () {
	if ($__jsx_profiler.resetResults == null)
		throw new Error("profiler has not been turned on");
	return $__jsx_profiler.resetResults();
};
JSX.DEBUG = true;
/**
 * class _Main extends Object
 * @constructor
 */
function _Main() {
}

/**
 * @constructor
 */
function _Main$() {
};

_Main$.prototype = new _Main;

/**
 * @param {Array.<undefined|!string>} args
 */
_Main.main$AS = function (args) {
	OktaviaSearch$setStemmer$LStemmer$(new EnglishStemmer$());
};

var _Main$main$AS = _Main.main$AS;

/**
 * class _Result extends Object
 * @constructor
 */
function _Result() {
}

/**
 * @constructor
 * @param {!string} title
 * @param {!string} url
 * @param {!string} content
 * @param {!number} score
 */
function _Result$SSSI(title, url, content, score) {
	this.title = title;
	this.url = url;
	this.content = content;
	this.score = score;
};

_Result$SSSI.prototype = new _Result;

/**
 * class _Proposal extends Object
 * @constructor
 */
function _Proposal() {
}

/**
 * @constructor
 * @param {!string} options
 * @param {!string} label
 * @param {!number} count
 */
function _Proposal$SSI(options, label, count) {
	this.options = options;
	this.label = label;
	this.count = count;
};

_Proposal$SSI.prototype = new _Proposal;

/**
 * class OktaviaSearch extends Object
 * @constructor
 */
function OktaviaSearch() {
}

/**
 * @constructor
 * @param {!number} entriesPerPage
 */
function OktaviaSearch$I(entriesPerPage) {
	this._queries = null;
	this._result = null;
	this._proposals = null;
	this._currentFolderDepth = 0;
	this._oktavia = new Oktavia$();
	this._entriesPerPage = entriesPerPage;
	this._currentPage = 1;
	this._queryString = null;
	this._callback = null;
	OktaviaSearch._instance = this;
};

OktaviaSearch$I.prototype = new OktaviaSearch;

/**
 * @param {Stemmer} stemmer
 */
OktaviaSearch.setStemmer$LStemmer$ = function (stemmer) {
	if (OktaviaSearch._instance) {
		OktaviaSearch._instance._oktavia.setStemmer$LStemmer$(stemmer);
	} else {
		OktaviaSearch._stemmer = stemmer;
	}
};

var OktaviaSearch$setStemmer$LStemmer$ = OktaviaSearch.setStemmer$LStemmer$;

/**
 * @param {!string} index
 */
OktaviaSearch.prototype.loadIndex$S = function (index) {
	if (OktaviaSearch._stemmer) {
		this._oktavia.setStemmer$LStemmer$(OktaviaSearch._stemmer);
	}
	this._oktavia.load$S(Binary$base64decode$S(index));
	if (this._queryString) {
		this.search$SF$IIV$((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[tool/web/oktavia-search.jsx:84:28] null access\n            this.search(this._queryString, this._callback);\n                            ^\n");
			}
			return v;
		}(this._queryString)), this._callback);
		this._queryString = null;
		this._callback = null;
	}
};

/**
 * @param {!string} queryString
 * @param {*} callback
 */
OktaviaSearch.prototype.search$SF$IIV$ = function (queryString, callback) {
	/** @type {QueryStringParser} */
	var queryParser;
	/** @type {SearchSummary} */
	var summary;
	if (this._oktavia) {
		queryParser = new QueryStringParser$();
		queryParser.parse$S(queryString);
		this._queries = queryParser.queries;
		summary = this._oktavia.search$ALQuery$(queryParser.queries);
		console.log(summary);
		if (summary.size$() > 0) {
			this._result = this._sortResult$LSearchSummary$(summary);
			this._proposals = [  ];
			this._currentPage = 1;
		} else {
			this._result = [  ];
			if (this._queries.length > 1) {
				this._proposals = summary.getProposal$();
			} else {
				this._proposals = [  ];
			}
			this._currentPage = 1;
		}
		callback(this.resultSize$(), this.totalPages$());
	} else {
		this._queryString = queryString;
		this._callback = callback;
	}
};

/**
 * @return {!number}
 */
OktaviaSearch.prototype.resultSize$ = function () {
	return (this._result.length | 0);
};

/**
 * @return {!number}
 */
OktaviaSearch.prototype.totalPages$ = function () {
	console.log(this._result.length);
	console.log(this._entriesPerPage);
	console.log(Math.ceil(this._result.length / this._entriesPerPage));
	return (Math.ceil(this._result.length / this._entriesPerPage) | 0);
};

/**
 * @return {!number}
 */
OktaviaSearch.prototype.currentPage$ = function () {
	return this._currentPage;
};

/**
 * @param {!number} page
 */
OktaviaSearch.prototype.setCurrentPage$I = function (page) {
	this._currentPage = page;
};

/**
 * @return {!boolean}
 */
OktaviaSearch.prototype.hasPrevPage$ = function () {
	return this._currentPage !== 1;
};

/**
 * @return {!boolean}
 */
OktaviaSearch.prototype.hasNextPage$ = function () {
	return this._currentPage !== this.totalPages$();
};

/**
 * @return {Array.<undefined|_Result>}
 */
OktaviaSearch.prototype.getResult$ = function () {
	/** @type {Style} */
	var style;
	/** @type {!number} */
	var start;
	/** @type {!number} */
	var last;
	/** @type {Metadata} */
	var metadata;
	/** @type {!number} */
	var num;
	/** @type {Array.<undefined|_Result>} */
	var results;
	/** @type {!number} */
	var i;
	/** @type {SearchUnit} */
	var unit;
	/** @type {Array.<undefined|!string>} */
	var info;
	/** @type {!number} */
	var offset;
	/** @type {!string} */
	var content;
	/** @type {Array.<undefined|Position>} */
	var positions;
	/** @type {!number} */
	var end;
	/** @type {!boolean} */
	var split;
	/** @type {!number} */
	var j;
	/** @type {Position} */
	var pos;
	/** @type {!string} */
	var text;
	style = new Style$S('html');
	start = (this._currentPage - 1) * this._entriesPerPage;
	last = Math.min(this._currentPage * this._entriesPerPage, this._result.length);
	metadata = this._oktavia.getPrimaryMetadata$();
	num = 250;
	results = [  ];
	for (i = start; i < last; i++) {
		unit = this._result[i];
		info = metadata.getInformation$I(unit.id).split(Oktavia.eob);
		offset = info[0].length + 1;
		content = metadata.getContent$I(unit.id);
		start = 0;
		positions = unit.getPositions$();
		if (content.indexOf((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[tool/web/oktavia-search.jsx:179:36] null access\n            if (content.indexOf(info[0]) == 1)\n                                    ^\n");
			}
			return v;
		}(info[0]))) === 1) {
			content = content.slice(info[0].length + 2, content.length);
			start += info[0].length + 2;
		}
		end = start + num;
		split = false;
		if (positions[0].position > end - positions[0].word.length) {
			end = positions[0].position + Math.floor(num / 2);
			split = true;
		}
		for (j = positions.length - 1; j > - 1; j--) {
			pos = positions[j];
			if (pos.position + pos.word.length < end) {
				content = [ content.slice(0, pos.position - start), style.convert$S('<hit>*</hit>').replace('*', content.slice(pos.position - start, pos.position + pos.word.length - start)), content.slice(pos.position + pos.word.length - start, content.length) ].join('');
			}
		}
		if (split) {
			text = [ content.slice(0, Math.floor(num / 2)) + ' ...', content.slice(- Math.floor(num / 2), end - start) ].join('<br/>');
		} else {
			text = content.slice(0, end - start) + ' ...<br/>';
		}
		text = text.replace(Oktavia.eob, ' ').replace(/(<br\/>)(<br\/>)+/, '<br/><br/>');
		results.push(new _Result$SSSI((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[tool/web/oktavia-search.jsx:215:41] null access\n            results.push(new _Result(info[0], info[1], text, unit.score));\n                                         ^\n");
			}
			return v;
		}(info[0])), (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[tool/web/oktavia-search.jsx:215:50] null access\n            results.push(new _Result(info[0], info[1], text, unit.score));\n                                                  ^\n");
			}
			return v;
		}(info[1])), text, unit.score));
	}
	return results;
};

/**
 * @return {Array.<undefined|_Proposal>}
 */
OktaviaSearch.prototype.getProposals$ = function () {
	/** @type {Style} */
	var style;
	/** @type {Array.<undefined|_Proposal>} */
	var results;
	/** @type {!number} */
	var i;
	/** @type {Proposal} */
	var proposal;
	/** @type {Array.<undefined|!string>} */
	var label;
	/** @type {Array.<undefined|!string>} */
	var option;
	/** @type {!number} */
	var j;
	style = new Style$S('html');
	results = [  ];
	if (this._queries.length > 1) {
		for (i = 0; i < this._proposals.length; i++) {
			proposal = this._proposals[i];
			label = [  ];
			option = [  ];
			for (j = 0; j < this._queries.length; j++) {
				if (j !== proposal.omit) {
					label.push(style.convert$S('<hit>' + this._queries[j].toString() + '</hit>'));
					option.push(this._queries[j].toString());
				} else {
					label.push(style.convert$S('<del>' + this._queries[j].toString() + '</del>'));
				}
			}
			results.push(new _Proposal$SSI(option.join(' '), label.join('&nbsp;'), proposal.expect));
		}
	}
	return results;
};

/**
 * @param {SearchSummary} summary
 * @return {Array.<undefined|SearchUnit>}
 */
OktaviaSearch.prototype._sortResult$LSearchSummary$ = function (summary) {
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var score;
	/** @type {SearchUnit} */
	var unit;
	/** @type {!string} */
	var pos;
	/** @type {Position} */
	var position;
	for (i = 0; i < summary.result.units.length; i++) {
		score = 0;
		unit = summary.result.units[i];
		for (pos in unit.positions) {
			position = unit.positions[pos];
			if (this._oktavia.wordPositionType$I(position.position)) {
				score += 10;
			} else {
				score += 1;
			}
			if (! position.stemmed) {
				score += 2;
			}
		}
		unit.score = (score | 0);
	}
	return summary.getSortedResult$();
};

/**
 * class _Main$0 extends Object
 * @constructor
 */
function _Main$0() {
}

/**
 * @constructor
 */
function _Main$0$() {
};

_Main$0$.prototype = new _Main$0;

/**
 * @param {Array.<undefined|!string>} args
 */
_Main$0.main$AS = function (args) {
};

var _Main$0$main$AS = _Main$0.main$AS;

/**
 * class Oktavia extends Object
 * @constructor
 */
function Oktavia() {
}

/**
 * @constructor
 */
function Oktavia$() {
	this._compressCode2utf16 = null;
	this._fmindex = new FMIndex$();
	this._metadatas = ({  });
	this._metadataLabels = [  ];
	this._stemmer = null;
	this._stemmingResult = ({  });
	this._utf162compressCode = [ Oktavia.eof, Oktavia.eob, Oktavia.unknown ];
	this._utf162compressCode.length = 65536;
	this._compressCode2utf16 = [ Oktavia.eof, Oktavia.eob, Oktavia.unknown ];
};

Oktavia$.prototype = new Oktavia;

/**
 * @param {Stemmer} stemmer
 */
Oktavia.prototype.setStemmer$LStemmer$ = function (stemmer) {
	this._stemmer = stemmer;
};

/**
 * @return {Metadata}
 */
Oktavia.prototype.getPrimaryMetadata$ = function () {
	return this._metadatas[this._metadataLabels[0]];
};

/**
 * @param {!string} key
 * @return {Section}
 */
Oktavia.prototype.addSection$S = function (key) {
	/** @type {Section} */
	var section;
	if (this._metadataLabels.indexOf(key) !== - 1) {
		throw new Error('Metadata name ' + key + ' is already exists');
	}
	this._metadataLabels.push(key);
	section = new Section$LOktavia$(this);
	this._metadatas[key] = section;
	return section;
};

/**
 * @param {!string} key
 * @return {Section}
 */
Oktavia.prototype.getSection$S = function (key) {
	if (this._metadataLabels.indexOf(key) === - 1) {
		throw new Error('Metadata name ' + key + " does't exists");
	}
	return (function (v) {
		if (! (v == null || v instanceof Section)) {
			debugger;
			throw new Error("[src/oktavia.jsx:67:36] detected invalid cast, value is not an instance of the designated type or null\n        return this._metadatas[key] as Section;\n                                    ^^\n");
		}
		return v;
	}(this._metadatas[key]));
};

/**
 * @param {!string} key
 * @return {Splitter}
 */
Oktavia.prototype.addSplitter$S = function (key) {
	/** @type {Splitter} */
	var splitter;
	if (this._metadataLabels.indexOf(key) !== - 1) {
		throw new Error('Metadata name ' + key + ' is already exists');
	}
	this._metadataLabels.push(key);
	splitter = new Splitter$LOktavia$(this);
	this._metadatas[key] = splitter;
	return splitter;
};

/**
 * @param {!string} key
 * @return {Splitter}
 */
Oktavia.prototype.getSplitter$S = function (key) {
	if (this._metadataLabels.indexOf(key) === - 1) {
		throw new Error('Metadata name ' + key + " does't exists");
	}
	return (function (v) {
		if (! (v == null || v instanceof Splitter)) {
			debugger;
			throw new Error("[src/oktavia.jsx:88:36] detected invalid cast, value is not an instance of the designated type or null\n        return this._metadatas[key] as Splitter;\n                                    ^^\n");
		}
		return v;
	}(this._metadatas[key]));
};

/**
 * @param {!string} key
 * @param {Array.<undefined|!string>} headers
 * @return {Table}
 */
Oktavia.prototype.addTable$SAS = function (key, headers) {
	/** @type {Table} */
	var table;
	if (this._metadataLabels.indexOf(key) !== - 1) {
		throw new Error('Metadata name ' + key + ' is already exists');
	}
	this._metadataLabels.push(key);
	table = new Table$LOktavia$AS(this, headers);
	this._metadatas[key] = table;
	return table;
};

/**
 * @param {!string} key
 * @return {Table}
 */
Oktavia.prototype.getTable$S = function (key) {
	if (this._metadataLabels.indexOf(key) === - 1) {
		throw new Error('Metadata name ' + key + " does't exists");
	}
	return (function (v) {
		if (! (v == null || v instanceof Table)) {
			debugger;
			throw new Error("[src/oktavia.jsx:109:36] detected invalid cast, value is not an instance of the designated type or null\n        return this._metadatas[key] as Table;\n                                    ^^\n");
		}
		return v;
	}(this._metadatas[key]));
};

/**
 * @param {!string} key
 * @return {Block}
 */
Oktavia.prototype.addBlock$S = function (key) {
	/** @type {Block} */
	var block;
	if (this._metadataLabels.indexOf(key) !== - 1) {
		throw new Error('Metadata name ' + key + ' is already exists');
	}
	this._metadataLabels.push(key);
	block = new Block$LOktavia$(this);
	this._metadatas[key] = block;
	return block;
};

/**
 * @param {!string} key
 * @return {Block}
 */
Oktavia.prototype.getBlock$S = function (key) {
	if (this._metadataLabels.indexOf(key) === - 1) {
		throw new Error('Metadata name ' + key + " does't exists");
	}
	return (function (v) {
		if (! (v == null || v instanceof Block)) {
			debugger;
			throw new Error("[src/oktavia.jsx:130:36] detected invalid cast, value is not an instance of the designated type or null\n        return this._metadatas[key] as Block;\n                                    ^^\n");
		}
		return v;
	}(this._metadatas[key]));
};

/**
 */
Oktavia.prototype.addEndOfBlock$ = function () {
	this._fmindex.push$S(Oktavia.eob);
};

/**
 * @param {!string} words
 */
Oktavia.prototype.addWord$S = function (words) {
	/** @type {Array.<undefined|!string>} */
	var str;
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var charCode;
	/** @type {undefined|!string} */
	var newCharCode;
	str = [  ];
	str.length = words.length;
	for (i = 0; i < words.length; i++) {
		charCode = words.charCodeAt(i);
		newCharCode = this._utf162compressCode[charCode];
		if (newCharCode == null) {
			newCharCode = String.fromCharCode(this._compressCode2utf16.length);
			this._utf162compressCode[charCode] = newCharCode;
			this._compressCode2utf16.push(String.fromCharCode(charCode));
		}
		str.push((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/oktavia.jsx:152:21] null access\n            str.push(newCharCode);\n                     ^^^^^^^^^^^\n");
			}
			return v;
		}(newCharCode)));
	}
	this._fmindex.push$S(str.join(''));
};

/**
 * @param {!string} words
 * @param {!boolean} stemming
 */
Oktavia.prototype.addWord$SB = function (words, stemming) {
	/** @type {Array.<undefined|!string>} */
	var wordList;
	/** @type {!number} */
	var i;
	/** @type {undefined|!string} */
	var originalWord;
	/** @type {!string} */
	var headSmall;
	/** @type {!string} */
	var baseWord;
	/** @type {!string} */
	var compressedCodeWord;
	/** @type {Array.<undefined|!string>} */
	var stemmedList;
	this.addWord$S(words);
	if (stemming && this._stemmer) {
		wordList = words.split(/\s+/);
		for (i = 0; i < wordList.length; i++) {
			originalWord = wordList[i];
			headSmall = originalWord.slice(0, 1).toLowerCase() + originalWord.slice(1);
			baseWord = this._stemmer.stemWord$S(originalWord.toLowerCase());
			if (originalWord.indexOf(baseWord) === - 1 && headSmall.indexOf(baseWord) === - 1) {
				compressedCodeWord = this._convertToCompressionCode$S((function (v) {
					if (! (v != null)) {
						debugger;
						throw new Error("[src/oktavia.jsx:170:76] null access\n                    var compressedCodeWord = this._convertToCompressionCode(originalWord);\n                                                                            ^^^^^^^^^^^^\n");
					}
					return v;
				}(originalWord)));
				stemmedList = this._stemmingResult[baseWord];
				if (! stemmedList) {
					stemmedList = [ compressedCodeWord ];
					this._stemmingResult[baseWord] = stemmedList;
				} else {
					if (stemmedList.indexOf(compressedCodeWord) === - 1) {
						stemmedList.push(compressedCodeWord);
					}
				}
			}
		}
	}
};

/**
 * @param {!string} keyword
 * @return {!string}
 */
Oktavia.prototype._convertToCompressionCode$S = function (keyword) {
	/** @type {Array.<undefined|!string>} */
	var resultChars;
	/** @type {!number} */
	var i;
	/** @type {undefined|!string} */
	var chr;
	resultChars = [  ];
	for (i = 0; i < keyword.length; i++) {
		chr = this._utf162compressCode[keyword.charCodeAt(i)];
		if (chr == null) {
			resultChars.push(Oktavia.unknown);
		} else {
			resultChars.push((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/oktavia.jsx:198:33] null access\n                resultChars.push(chr);\n                                 ^^^\n");
				}
				return v;
			}(chr)));
		}
	}
	return resultChars.join('');
};

/**
 * @param {!string} keyword
 * @param {!boolean} stemming
 * @return {Array.<undefined|!number>}
 */
Oktavia.prototype.rawSearch$SB = function (keyword, stemming) {
	/** @type {Array.<undefined|!number>} */
	var result;
	/** @type {!string} */
	var baseWord;
	/** @type {Array.<undefined|!string>} */
	var stemmedList;
	/** @type {!number} */
	var i;
	/** @type {undefined|!string} */
	var word;
	if (stemming) {
		result = [  ];
		if (this._stemmer) {
			baseWord = this._stemmer.stemWord$S(keyword.toLowerCase());
			stemmedList = this._stemmingResult[baseWord];
			if (stemmedList) {
				for (i = 0; i < stemmedList.length; i++) {
					word = stemmedList[i];
					result = result.concat(this._fmindex.search$S((function (v) {
						if (! (v != null)) {
							debugger;
							throw new Error("[src/oktavia.jsx:219:68] null access\n                        result = result.concat(this._fmindex.search(word));\n                                                                    ^^^^\n");
						}
						return v;
					}(word))));
				}
			}
		}
	} else {
		result = this._fmindex.search$S(this._convertToCompressionCode$S(keyword));
	}
	return result;
};

/**
 * @param {Array.<undefined|Query>} queries
 * @return {SearchSummary}
 */
Oktavia.prototype.search$ALQuery$ = function (queries) {
	/** @type {SearchSummary} */
	var summary;
	/** @type {!number} */
	var i;
	summary = new SearchSummary$LOktavia$(this);
	for (i = 0; i < queries.length; i++) {
		summary.addQuery$LSingleResult$(this._searchQuery$LQuery$(queries[i]));
	}
	summary.mergeResult$();
	return summary;
};

/**
 * @param {Query} query
 * @return {SingleResult}
 */
Oktavia.prototype._searchQuery$LQuery$ = function (query) {
	/** @type {SingleResult} */
	var result;
	/** @type {Array.<undefined|!number>} */
	var positions;
	result = new SingleResult$SBB(query.word, query.or, query.not);
	if (query.raw) {
		positions = this.rawSearch$SB(query.word, false);
	} else {
		positions = this.rawSearch$SB(query.word, false).concat(this.rawSearch$SB(query.word, true));
	}
	this.getPrimaryMetadata$().grouping$LSingleResult$AISB(result, positions, query.word, ! query.raw);
	return result;
};

/**
 */
Oktavia.prototype.build$ = function () {
	this.build$IB(5, false);
};

/**
 * @param {!number} cacheDensity
 * @param {!boolean} verbose
 */
Oktavia.prototype.build$IB = function (cacheDensity, verbose) {
	/** @type {!string} */
	var key;
	/** @type {!number} */
	var cacheRange;
	/** @type {!number} */
	var maxChar;
	for (key in this._metadatas) {
		this._metadatas[key]._build$();
	}
	cacheRange = Math.round(Math.max(1, 100 / Math.min(100, Math.max(0.01, cacheDensity))));
	maxChar = this._compressCode2utf16.length;
	this._fmindex.build$SIIB(Oktavia.eof, maxChar, cacheRange, verbose);
};

/**
 * @return {!string}
 */
Oktavia.prototype.dump$ = function () {
	return this.dump$B(false);
};

/**
 * @param {!boolean} verbose
 * @return {!string}
 */
Oktavia.prototype.dump$B = function (verbose) {
	/** @type {!string} */
	var headerSource;
	/** @type {!string} */
	var header;
	/** @type {!string} */
	var fmdata;
	/** @type {Array.<undefined|!string>} */
	var result;
	/** @type {!number} */
	var i;
	/** @type {CompressionReport} */
	var report;
	/** @type {undefined|!string} */
	var name;
	/** @type {!string} */
	var data;
	headerSource = "oktavia-01";
	header = Binary$dumpString$S(headerSource).slice(1);
	if (verbose) {
		console.log("Source text size: " + (this._fmindex.size$() * 2 + "") + ' bytes');
	}
	fmdata = this._fmindex.dump$B(verbose);
	result = [ header, fmdata ];
	result.push(Binary$dump16bitNumber$I(this._compressCode2utf16.length));
	for (i = 3; i < this._compressCode2utf16.length; i++) {
		result.push((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/oktavia.jsx:296:48] null access\n            result.push(this._compressCode2utf16[i]);\n                                                ^\n");
			}
			return v;
		}(this._compressCode2utf16[i])));
	}
	if (verbose) {
		console.log('Char Code Map: ' + (this._compressCode2utf16.length * 2 - 2 + "") + ' bytes');
	}
	report = new CompressionReport$();
	result.push(Binary$dumpStringListMap$HASLCompressionReport$(this._stemmingResult, report));
	if (verbose) {
		console.log('Stemmed Word Table: ' + (result[result.length - 1].length + "") + ' bytes (' + (report.rate$() + "") + '%)');
		console.log(this._stemmingResult);
	}
	result.push(Binary$dump16bitNumber$I(this._metadataLabels.length));
	for (i = 0; i < this._metadataLabels.length; i++) {
		report = new CompressionReport$();
		name = this._metadataLabels[i];
		data = this._metadatas[name]._dump$LCompressionReport$(report);
		result.push(Binary$dumpString$SLCompressionReport$((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/oktavia.jsx:317:42] null access\n            result.push(Binary.dumpString(name, report), data);\n                                          ^^^^\n");
			}
			return v;
		}(name)), report), data);
		if (verbose) {
			console.log('Meta Data ' + (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/oktavia.jsx:320:43] null access\n                console.log(\'Meta Data \' + name + \': \' + (data.length * 2) as string + \' bytes (\' + report.rate() as string + \'%)\');\n                                           ^^^^\n");
				}
				return v;
			}(name)) + ': ' + (data.length * 2 + "") + ' bytes (' + (report.rate$() + "") + '%)');
		}
	}
	return result.join('');
};

/**
 * @param {!string} data
 */
Oktavia.prototype.load$S = function (data) {
	/** @type {!string} */
	var headerSource;
	/** @type {!string} */
	var header;
	/** @type {!number} */
	var offset;
	/** @type {!number} */
	var charCodeCount;
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var charCode;
	/** @type {LoadedStringListMapResult} */
	var stemmedWords;
	/** @type {!number} */
	var metadataCount;
	/** @type {LoadedStringResult} */
	var nameResult;
	/** @type {!string} */
	var name;
	/** @type {!number} */
	var type;
	headerSource = "oktavia-01";
	header = Binary$dumpString$S(headerSource).slice(1);
	if (data.slice(0, 5) !== header) {
		throw new Error('Invalid data file');
	}
	this._metadatas = ({  });
	this._metadataLabels = [  ];
	offset = 5;
	offset = this._fmindex.load$SI(data, offset);
	charCodeCount = Binary$load16bitNumber$SI(data, offset++);
	this._compressCode2utf16 = [ Oktavia.eof, Oktavia.eob, Oktavia.unknown ];
	this._utf162compressCode = [ Oktavia.eof, Oktavia.eob, Oktavia.unknown ];
	for (i = 3; i < charCodeCount; i++) {
		charCode = Binary$load16bitNumber$SI(data, offset++);
		this._compressCode2utf16.push(String.fromCharCode(charCode));
		this._utf162compressCode[charCode] = String.fromCharCode(i);
	}
	stemmedWords = Binary$loadStringListMap$SI(data, offset);
	this._stemmingResult = stemmedWords.result;
	offset = stemmedWords.offset;
	metadataCount = Binary$load16bitNumber$SI(data, offset++);
	for (i = 0; i < metadataCount; i++) {
		nameResult = Binary$loadString$SI(data, offset);
		name = nameResult.result;
		offset = nameResult.offset;
		type = Binary$load16bitNumber$SI(data, offset++);
		switch (type) {
		case 0:
			offset = Section$_load$LOktavia$SSI(this, name, data, offset);
			break;
		case 1:
			offset = Splitter$_load$LOktavia$SSI(this, name, data, offset);
			break;
		case 2:
			offset = Table$_load$LOktavia$SSI(this, name, data, offset);
			break;
		case 3:
			offset = Block$_load$LOktavia$SSI(this, name, data, offset);
			break;
		}
	}
};

/**
 * @return {!number}
 */
Oktavia.prototype.contentSize$ = function () {
	return this._fmindex.contentSize$();
};

/**
 * @param {!number} position
 * @return {!number}
 */
Oktavia.prototype.wordPositionType$I = function (position) {
	/** @type {!number} */
	var result;
	/** @type {!string} */
	var ahead;
	result = 0;
	if (position === 0) {
		result = 4;
	} else {
		ahead = this._fmindex.getSubstring$II(position - 1, 1);
		if (/\s/.test(ahead)) {
			result = 2;
		} else {
			if (/\W/.test(ahead)) {
				result = 1;
			} else {
				if (Oktavia.eob === ahead) {
					result = 3;
				}
			}
		}
	}
	return (result | 0);
};

/**
 * @param {!number} position
 * @param {!number} length
 * @return {!string}
 */
Oktavia.prototype._getSubstring$II = function (position, length) {
	/** @type {!string} */
	var result;
	/** @type {Array.<undefined|!string>} */
	var str;
	/** @type {!number} */
	var i;
	result = this._fmindex.getSubstring$II(position, length);
	str = [  ];
	for (i = 0; i < result.length; i++) {
		str.push((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/oktavia.jsx:415:45] null access\n            str.push(this._compressCode2utf16[result.charCodeAt(i)]);\n                                             ^\n");
			}
			return v;
		}(this._compressCode2utf16[result.charCodeAt(i)])));
	}
	return str.join('');
};

/**
 * class Binary extends Object
 * @constructor
 */
function Binary() {
}

/**
 * @constructor
 */
function Binary$() {
};

Binary$.prototype = new Binary;

/**
 * @param {!number} num
 * @return {!string}
 */
Binary.dump32bitNumber$N = function (num) {
	/** @type {Array.<undefined|!string>} */
	var result;
	result = [ String.fromCharCode(Math.floor(num / 65536)) ];
	result.push(String.fromCharCode(num % 65536));
	return result.join("");
};

var Binary$dump32bitNumber$N = Binary.dump32bitNumber$N;

/**
 * @param {!string} buffer
 * @param {!number} offset
 * @return {!number}
 */
Binary.load32bitNumber$SI = function (buffer, offset) {
	/** @type {!number} */
	var result;
	result = buffer.charCodeAt(offset) * 65536 + buffer.charCodeAt(offset + 1);
	return result;
};

var Binary$load32bitNumber$SI = Binary.load32bitNumber$SI;

/**
 * @param {!number} num
 * @return {!string}
 */
Binary.dump16bitNumber$I = function (num) {
	return String.fromCharCode(num % 65536);
};

var Binary$dump16bitNumber$I = Binary.dump16bitNumber$I;

/**
 * @param {!string} buffer
 * @param {!number} offset
 * @return {!number}
 */
Binary.load16bitNumber$SI = function (buffer, offset) {
	return (buffer.charCodeAt(offset) | 0);
};

var Binary$load16bitNumber$SI = Binary.load16bitNumber$SI;

/**
 * @param {!string} str
 * @return {!string}
 */
Binary.dumpString$S = function (str) {
	return Binary$dumpString$SLCompressionReport$(str, null);
};

var Binary$dumpString$S = Binary.dumpString$S;

/**
 * @param {!string} str
 * @param {CompressionReport} report
 * @return {!string}
 */
Binary.dumpString$SLCompressionReport$ = function (str, report) {
	/** @type {!number} */
	var length;
	/** @type {!boolean} */
	var compress;
	/** @type {Array.<undefined|!number>} */
	var charCodes;
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var charCode;
	/** @type {Array.<undefined|!string>} */
	var result;
	/** @type {undefined|!number} */
	var bytes;
	if (str.length > 32768) {
		str = str.slice(0, 32768);
	}
	length = str.length;
	compress = true;
	charCodes = [  ];
	for (i = 0; i < length; i++) {
		charCode = str.charCodeAt(i);
		if (charCode > 255) {
			compress = false;
			break;
		}
		charCodes.push(charCode);
	}
	if (compress) {
		result = [ Binary$dump16bitNumber$I(length + 32768) ];
		for (i = 0; i < length; i += 2) {
			bytes = charCodes[i];
			if (i !== length - 1) {
				bytes += (function (v) {
					if (! (v != null)) {
						debugger;
						throw new Error("[src/binary-util.jsx:58:38] null access\n                    bytes += charCodes[i + 1] << 8;\n                                      ^\n");
					}
					return v;
				}(charCodes[i + 1])) << 8;
			}
			result.push(Binary$dump16bitNumber$I((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/binary-util.jsx:60:51] null access\n                result.push(Binary.dump16bitNumber(bytes));\n                                                   ^^^^^\n");
				}
				return v;
			}(bytes))));
		}
		if (report) {
			report.add$II(length, Math.ceil(length / 2));
		}
	} else {
		result = [ Binary$dump16bitNumber$I(length), str ];
		if (report) {
			report.add$II(length, length);
		}
	}
	return result.join('');
};

var Binary$dumpString$SLCompressionReport$ = Binary.dumpString$SLCompressionReport$;

/**
 * @param {!string} buffer
 * @param {!number} offset
 * @return {LoadedStringResult}
 */
Binary.loadString$SI = function (buffer, offset) {
	return new LoadedStringResult$SI(buffer, offset);
};

var Binary$loadString$SI = Binary.loadString$SI;

/**
 * @param {Array.<undefined|!string>} strList
 * @return {!string}
 */
Binary.dumpStringList$AS = function (strList) {
	return Binary$dumpStringList$ASLCompressionReport$(strList, null);
};

var Binary$dumpStringList$AS = Binary.dumpStringList$AS;

/**
 * @param {Array.<undefined|!string>} strList
 * @param {CompressionReport} report
 * @return {!string}
 */
Binary.dumpStringList$ASLCompressionReport$ = function (strList, report) {
	/** @type {Array.<undefined|!string>} */
	var result;
	/** @type {!number} */
	var i;
	result = [ Binary$dump32bitNumber$N(strList.length) ];
	for (i = 0; i < strList.length; i++) {
		result.push(Binary$dumpString$SLCompressionReport$((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/binary-util.jsx:93:49] null access\n            result.push(Binary.dumpString(strList[i], report));\n                                                 ^\n");
			}
			return v;
		}(strList[i])), report));
	}
	return result.join('');
};

var Binary$dumpStringList$ASLCompressionReport$ = Binary.dumpStringList$ASLCompressionReport$;

/**
 * @param {!string} buffer
 * @param {!number} offset
 * @return {LoadedStringListResult}
 */
Binary.loadStringList$SI = function (buffer, offset) {
	return new LoadedStringListResult$SI(buffer, offset);
};

var Binary$loadStringList$SI = Binary.loadStringList$SI;

/**
 * @param {Object.<string, undefined|Array.<undefined|!string>>} strMap
 * @return {!string}
 */
Binary.dumpStringListMap$HAS = function (strMap) {
	return Binary$dumpStringListMap$HASLCompressionReport$(strMap, null);
};

var Binary$dumpStringListMap$HAS = Binary.dumpStringListMap$HAS;

/**
 * @param {Object.<string, undefined|Array.<undefined|!string>>} strMap
 * @param {CompressionReport} report
 * @return {!string}
 */
Binary.dumpStringListMap$HASLCompressionReport$ = function (strMap, report) {
	/** @type {Array.<undefined|!string>} */
	var result;
	/** @type {!number} */
	var counter;
	/** @type {!string} */
	var key;
	result = [  ];
	counter = 0;
	for (key in strMap) {
		result.push(Binary$dumpString$SLCompressionReport$(key, report));
		result.push(Binary$dumpStringList$ASLCompressionReport$(strMap[key], report));
		counter++;
	}
	return Binary$dump32bitNumber$N(counter) + result.join('');
};

var Binary$dumpStringListMap$HASLCompressionReport$ = Binary.dumpStringListMap$HASLCompressionReport$;

/**
 * @param {!string} buffer
 * @param {!number} offset
 * @return {LoadedStringListMapResult}
 */
Binary.loadStringListMap$SI = function (buffer, offset) {
	return new LoadedStringListMapResult$SI(buffer, offset);
};

var Binary$loadStringListMap$SI = Binary.loadStringListMap$SI;

/**
 * @param {Array.<undefined|!number>} array
 * @return {!string}
 */
Binary.dump32bitNumberList$AN = function (array) {
	return Binary$dump32bitNumberList$ANLCompressionReport$(array, null);
};

var Binary$dump32bitNumberList$AN = Binary.dump32bitNumberList$AN;

/**
 * @param {Array.<undefined|!number>} array
 * @param {CompressionReport} report
 * @return {!string}
 */
Binary.dump32bitNumberList$ANLCompressionReport$ = function (array, report) {
	/** @type {Array.<undefined|!string>} */
	var result;
	/** @type {!number} */
	var index;
	/** @type {!number} */
	var inputLength;
	/** @type {!number} */
	var length;
	/** @type {!string} */
	var resultString;
	result = [ Binary$dump32bitNumber$N(array.length) ];
	index = 0;
	inputLength = array.length;
	while (index < inputLength) {
		if (array[index] == 0) {
			length = Binary$_countZero$ANI(array, index);
			result.push(Binary$_zeroBlock$I(length));
			index += length;
		} else {
			if (Binary$_shouldZebraCode$ANI(array, index)) {
				result.push(Binary$_createZebraCode$ANI(array, index));
				index = Math.min(array.length, index + 15);
			} else {
				length = Binary$_searchDoubleZero$ANI(array, index);
				result.push(Binary$_nonZeroBlock$ANII(array, index, length));
				if (length === 0) {
					throw new Error('');
				}
				index += length;
			}
		}
	}
	resultString = result.join('');
	if (report) {
		report.add$II(array.length * 2 + 2, resultString.length);
	}
	return resultString;
};

var Binary$dump32bitNumberList$ANLCompressionReport$ = Binary.dump32bitNumberList$ANLCompressionReport$;

/**
 * @param {!string} buffer
 * @param {!number} offset
 * @return {LoadedNumberListResult}
 */
Binary.load32bitNumberList$SI = function (buffer, offset) {
	return new LoadedNumberListResult$SI(buffer, offset);
};

var Binary$load32bitNumberList$SI = Binary.load32bitNumberList$SI;

/**
 * @param {Array.<undefined|!number>} array
 * @param {!number} offset
 * @return {!number}
 */
Binary._countZero$ANI = function (array, offset) {
	/** @type {!number} */
	var i;
	for (i = offset; i < array.length; i++) {
		if (array[i] != 0) {
			return (i - offset | 0);
		}
	}
	return (array.length - offset | 0);
};

var Binary$_countZero$ANI = Binary._countZero$ANI;

/**
 * @param {!number} length
 * @return {!string}
 */
Binary._zeroBlock$I = function (length) {
	/** @type {Array.<undefined|!string>} */
	var result;
	result = [  ];
	while (length > 0) {
		if (length > 16384) {
			result.push(Binary$dump16bitNumber$I(16384 - 1));
			length -= 16384;
		} else {
			result.push(Binary$dump16bitNumber$I(length - 1));
			length = 0;
		}
	}
	return result.join('');
};

var Binary$_zeroBlock$I = Binary._zeroBlock$I;

/**
 * @param {Array.<undefined|!number>} array
 * @param {!number} offset
 * @return {!boolean}
 */
Binary._shouldZebraCode$ANI = function (array, offset) {
	/** @type {!number} */
	var change;
	/** @type {!boolean} */
	var isLastZero;
	/** @type {!number} */
	var i;
	if (array.length - offset < 16) {
		return true;
	}
	change = 0;
	isLastZero = false;
	for (i = offset; i < offset + 15; i++) {
		if (array[i] == 0) {
			if (! isLastZero) {
				isLastZero = true;
				change++;
			}
		} else {
			if (isLastZero) {
				isLastZero = false;
				change++;
			}
		}
	}
	return change > 2;
};

var Binary$_shouldZebraCode$ANI = Binary._shouldZebraCode$ANI;

/**
 * @param {Array.<undefined|!number>} array
 * @param {!number} offset
 * @return {!number}
 */
Binary._searchDoubleZero$ANI = function (array, offset) {
	/** @type {!boolean} */
	var isLastZero;
	/** @type {!number} */
	var i;
	isLastZero = false;
	for (i = offset; i < array.length; i++) {
		if (array[i] == 0) {
			if (isLastZero) {
				return (i - offset - 1 | 0);
			}
			isLastZero = true;
		} else {
			isLastZero = false;
		}
	}
	return (array.length - offset | 0);
};

var Binary$_searchDoubleZero$ANI = Binary._searchDoubleZero$ANI;

/**
 * @param {Array.<undefined|!number>} array
 * @param {!number} offset
 * @param {!number} length
 * @return {!string}
 */
Binary._nonZeroBlock$ANII = function (array, offset, length) {
	/** @type {Array.<undefined|!string>} */
	var result;
	/** @type {!number} */
	var blockLength;
	/** @type {!number} */
	var i;
	result = [  ];
	while (length > 0) {
		if (length > 16384) {
			blockLength = 16384;
			length -= 16384;
		} else {
			blockLength = length;
			length = 0;
		}
		result.push(Binary$dump16bitNumber$I(blockLength - 1 + 0x4000));
		for (i = offset; i < offset + blockLength; i++) {
			result.push(Binary$dump32bitNumber$N((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/binary-util.jsx:274:56] null access\n                result.push(Binary.dump32bitNumber(array[i]));\n                                                        ^\n");
				}
				return v;
			}(array[i]))));
		}
		offset += blockLength;
	}
	return result.join('');
};

var Binary$_nonZeroBlock$ANII = Binary._nonZeroBlock$ANII;

/**
 * @param {Array.<undefined|!number>} array
 * @param {!number} offset
 * @return {!string}
 */
Binary._createZebraCode$ANI = function (array, offset) {
	/** @type {!number} */
	var last;
	/** @type {!number} */
	var code;
	/** @type {Array.<undefined|!string>} */
	var result;
	/** @type {!number} */
	var i;
	last = Math.min(offset + 15, array.length);
	code = 0x8000;
	result = [  ];
	for (i = offset; i < last; i++) {
		if (array[i] != 0) {
			result.push(Binary$dump32bitNumber$N((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/binary-util.jsx:290:56] null access\n                result.push(Binary.dump32bitNumber(array[i]));\n                                                        ^\n");
				}
				return v;
			}(array[i]))));
			code = code + (0x1 << i - offset);
		}
	}
	return String.fromCharCode(code) + result.join('');
};

var Binary$_createZebraCode$ANI = Binary._createZebraCode$ANI;

/**
 * @param {!string} str
 * @return {!string}
 */
Binary.base64encode$S = function (str) {
	/** @type {Array.<undefined|!string>} */
	var out;
	/** @type {Array.<undefined|!number>} */
	var source;
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var code;
	/** @type {!number} */
	var len;
	/** @type {!number} */
	var c1;
	/** @type {undefined|!number} */
	var c2;
	/** @type {undefined|!number} */
	var c3;
	out = [  ];
	source = [  ];
	for (i = 0; i < str.length; i++) {
		code = str.charCodeAt(i);
		source.push(code & 0x00ff, code >>> 8);
	}
	len = str.length * 2;
	i = 0;
	while (i < len) {
		c1 = (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/binary-util.jsx:319:23] null access\n        var c1 = source[i++] & 0xff;\n                       ^\n");
			}
			return v;
		}(source[i++])) & 0xff;
		if (i === len) {
			out.push(Binary._base64EncodeChars.charAt(c1 >> 2));
			out.push(Binary._base64EncodeChars.charAt((c1 & 0x3) << 4));
			out.push("==");
			break;
		}
		c2 = source[i++];
		if (i === len) {
			out.push(Binary._base64EncodeChars.charAt(c1 >> 2));
			out.push(Binary._base64EncodeChars.charAt((c1 & 0x3) << 4 | ((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/binary-util.jsx:331:75] null access\n            out.push(Binary._base64EncodeChars.charAt(((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)));\n                                                                           ^^\n");
				}
				return v;
			}(c2)) & 0xF0) >> 4));
			out.push(Binary._base64EncodeChars.charAt(((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/binary-util.jsx:332:55] null access\n            out.push(Binary._base64EncodeChars.charAt((c2 & 0xF) << 2));\n                                                       ^^\n");
				}
				return v;
			}(c2)) & 0xF) << 2));
			out.push("=");
			break;
		}
		c3 = source[i++];
		out.push(Binary._base64EncodeChars.charAt(c1 >> 2));
		out.push(Binary._base64EncodeChars.charAt((c1 & 0x3) << 4 | ((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/binary-util.jsx:338:71] null access\n        out.push(Binary._base64EncodeChars.charAt(((c1 & 0x3)<< 4) | ((c2 & 0xF0) >> 4)));\n                                                                       ^^\n");
			}
			return v;
		}(c2)) & 0xF0) >> 4));
		out.push(Binary._base64EncodeChars.charAt(((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/binary-util.jsx:339:52] null access\n        out.push(Binary._base64EncodeChars.charAt(((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)));\n                                                    ^^\n");
			}
			return v;
		}(c2)) & 0xF) << 2 | ((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/binary-util.jsx:339:72] null access\n        out.push(Binary._base64EncodeChars.charAt(((c2 & 0xF) << 2) | ((c3 & 0xC0) >>6)));\n                                                                        ^^\n");
			}
			return v;
		}(c3)) & 0xC0) >> 6));
		out.push(Binary._base64EncodeChars.charAt((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/binary-util.jsx:340:50] null access\n        out.push(Binary._base64EncodeChars.charAt(c3 & 0x3F));\n                                                  ^^\n");
			}
			return v;
		}(c3)) & 0x3F));
	}
	return out.join('');
};

var Binary$base64encode$S = Binary.base64encode$S;

/**
 * @param {Array.<undefined|!number>} source
 * @return {!string}
 */
Binary._mergeCharCode$AI = function (source) {
	/** @type {Array.<undefined|!string>} */
	var result;
	/** @type {!number} */
	var i;
	result = [  ];
	for (i = 0; i < source.length; i += 2) {
		result.push(String.fromCharCode((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/binary-util.jsx:360:50] null access\n            result.push(String.fromCharCode(source[i] + (source[i + 1] << 8)));\n                                                  ^\n");
			}
			return v;
		}(source[i])) + ((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/binary-util.jsx:360:63] null access\n            result.push(String.fromCharCode(source[i] + (source[i + 1] << 8)));\n                                                               ^\n");
			}
			return v;
		}(source[i + 1])) << 8)));
	}
	return result.join('');
};

var Binary$_mergeCharCode$AI = Binary._mergeCharCode$AI;

/**
 * @param {!string} str
 * @return {!string}
 */
Binary.base64decode$S = function (str) {
	/** @type {!number} */
	var len;
	/** @type {!number} */
	var i;
	/** @type {Array.<undefined|!number>} */
	var out;
	/** @type {undefined|!number} */
	var c1;
	/** @type {undefined|!number} */
	var c2;
	/** @type {!number} */
	var c3;
	/** @type {!number} */
	var c4;
	len = str.length;
	i = 0;
	out = [  ];
	while (i < len) {
		do {
			c1 = Binary._base64DecodeChars[str.charCodeAt(i++) & 0xff];
		} while (i < len && c1 == - 1);
		if (c1 == - 1) {
			break;
		}
		do {
			c2 = Binary._base64DecodeChars[str.charCodeAt(i++) & 0xff];
		} while (i < len && c2 == - 1);
		if (c2 == - 1) {
			break;
		}
		out.push((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/binary-util.jsx:391:18] null access\n        out.push((c1 << 2) | ((c2 & 0x30) >> 4));\n                  ^^\n");
			}
			return v;
		}(c1)) << 2 | ((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/binary-util.jsx:391:31] null access\n        out.push((c1 << 2) | ((c2 & 0x30) >> 4));\n                               ^^\n");
			}
			return v;
		}(c2)) & 0x30) >> 4);
		do {
			c3 = str.charCodeAt(i++) & 0xff;
			if (c3 === 61) {
				return Binary$_mergeCharCode$AI(out);
			}
			c3 = (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/binary-util.jsx:399:42] null access\n            c3 = Binary._base64DecodeChars[c3];\n                                          ^\n");
				}
				return v;
			}(Binary._base64DecodeChars[c3]));
		} while (i < len && c3 === - 1);
		if (c3 === - 1) {
			break;
		}
		out.push(((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/binary-util.jsx:405:19] null access\n        out.push(((c2 & 0XF) << 4) | ((c3 & 0x3C) >> 2));\n                   ^^\n");
			}
			return v;
		}(c2)) & 0XF) << 4 | (c3 & 0x3C) >> 2);
		do {
			c4 = str.charCodeAt(i++) & 0xff;
			if (c4 === 61) {
				return Binary$_mergeCharCode$AI(out);
			}
			c4 = ((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/binary-util.jsx:414:42] null access\n            c4 = Binary._base64DecodeChars[c4];\n                                          ^\n");
				}
				return v;
			}(Binary._base64DecodeChars[c4])) | 0);
		} while (i < len && c4 === - 1);
		if (c4 === - 1) {
			break;
		}
		out.push((c3 & 0x03) << 6 | c4);
	}
	return Binary$_mergeCharCode$AI(out);
};

var Binary$base64decode$S = Binary.base64decode$S;

/**
 * class LoadedStringResult extends Object
 * @constructor
 */
function LoadedStringResult() {
}

/**
 * @constructor
 * @param {!string} data
 * @param {!number} offset
 */
function LoadedStringResult$SI(data, offset) {
	/** @type {!number} */
	var strLength;
	/** @type {Array.<undefined|!string>} */
	var bytes;
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var code;
	this.result = "";
	this.offset = 0;
	strLength = Binary$load16bitNumber$SI(data, offset++);
	if (strLength > 32767) {
		strLength = strLength - 32768;
		bytes = [  ];
		for (i = 0; i < strLength; i += 2) {
			code = data.charCodeAt(offset);
			bytes.push(String.fromCharCode(code & 0x00ff));
			if (i !== strLength - 1) {
				bytes.push(String.fromCharCode(code >>> 8));
			}
			offset++;
		}
		this.result = bytes.join('');
		this.offset = offset;
	} else {
		this.result = data.slice(offset, offset + strLength);
		this.offset = (offset + strLength | 0);
	}
};

LoadedStringResult$SI.prototype = new LoadedStringResult;

/**
 * class LoadedStringListResult extends Object
 * @constructor
 */
function LoadedStringListResult() {
}

/**
 * @constructor
 * @param {!string} data
 * @param {!number} offset
 */
function LoadedStringListResult$SI(data, offset) {
	/** @type {!number} */
	var length;
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var strLength;
	/** @type {!string} */
	var resultStr;
	/** @type {Array.<undefined|!string>} */
	var bytes;
	/** @type {!number} */
	var j;
	/** @type {!number} */
	var code;
	this.offset = 0;
	this.result = [  ];
	length = Binary$load32bitNumber$SI(data, offset);
	offset += 2;
	for (i = 0; i < length; i++) {
		strLength = Binary$load16bitNumber$SI(data, offset++);
		if (strLength > 32767) {
			strLength = strLength - 32768;
			bytes = [  ];
			for (j = 0; j < strLength; j += 2) {
				code = data.charCodeAt(offset);
				bytes.push(String.fromCharCode(code & 0x00ff));
				if (j !== strLength - 1) {
					bytes.push(String.fromCharCode(code >>> 8));
				}
				offset++;
			}
			resultStr = bytes.join('');
		} else {
			resultStr = data.slice(offset, offset + strLength);
			offset = (offset + strLength | 0);
		}
		this.result.push(resultStr);
	}
	this.offset = offset;
};

LoadedStringListResult$SI.prototype = new LoadedStringListResult;

/**
 * class LoadedStringListMapResult extends Object
 * @constructor
 */
function LoadedStringListMapResult() {
}

/**
 * @constructor
 * @param {!string} data
 * @param {!number} offset
 */
function LoadedStringListMapResult$SI(data, offset) {
	/** @type {!number} */
	var length;
	/** @type {!number} */
	var i;
	/** @type {LoadedStringResult} */
	var keyResult;
	/** @type {LoadedStringListResult} */
	var valueResult;
	this.offset = 0;
	this.result = ({  });
	length = Binary$load32bitNumber$SI(data, offset);
	offset += 2;
	for (i = 0; i < length; i++) {
		keyResult = Binary$loadString$SI(data, offset);
		valueResult = Binary$loadStringList$SI(data, keyResult.offset);
		this.result[keyResult.result] = valueResult.result;
		offset = valueResult.offset;
	}
	this.offset = offset;
};

LoadedStringListMapResult$SI.prototype = new LoadedStringListMapResult;

/**
 * class LoadedNumberListResult extends Object
 * @constructor
 */
function LoadedNumberListResult() {
}

/**
 * @constructor
 * @param {!string} data
 * @param {!number} offset
 */
function LoadedNumberListResult$SI(data, offset) {
	/** @type {!number} */
	var resultLength;
	/** @type {!number} */
	var originalOffset;
	/** @type {Array.<undefined|!number>} */
	var result;
	/** @type {!number} */
	var tag;
	/** @type {!number} */
	var length;
	/** @type {!number} */
	var i;
	this.result = null;
	this.offset = 0;
	resultLength = Binary$load32bitNumber$SI(data, offset);
	originalOffset = offset;
	offset += 2;
	result = [  ];
	while (result.length < resultLength) {
		tag = data.charCodeAt(offset++);
		if (tag >>> 15 === 1) {
			length = Math.min(resultLength - result.length, 15);
			for (i = 0; i < length; i++) {
				if (tag >>> i & 0x1) {
					result.push(Binary$load32bitNumber$SI(data, offset));
					offset += 2;
				} else {
					result.push(0);
				}
			}
		} else {
			if (tag >>> 14 === 1) {
				length = tag - 0x4000 + 1;
				for (i = 0; i < length; i++) {
					result.push(Binary$load32bitNumber$SI(data, offset));
					offset += 2;
				}
			} else {
				length = tag + 1;
				for (i = 0; i < length; i++) {
					result.push(0);
				}
			}
		}
	}
	this.result = result;
	this.offset = offset;
};

LoadedNumberListResult$SI.prototype = new LoadedNumberListResult;

/**
 * class CompressionReport extends Object
 * @constructor
 */
function CompressionReport() {
}

/**
 * @constructor
 */
function CompressionReport$() {
	this.source = 0;
	this.result = 0;
};

CompressionReport$.prototype = new CompressionReport;

/**
 * @param {!number} source
 * @param {!number} result
 */
CompressionReport.prototype.add$II = function (source, result) {
	this.source += source;
	this.result += result;
};

/**
 * @return {!number}
 */
CompressionReport.prototype.rate$ = function () {
	return (Math.round(this.result * 100.0 / this.source) | 0);
};

/**
 * class Query extends Object
 * @constructor
 */
function Query() {
}

/**
 * @constructor
 */
function Query$() {
	this.word = '';
	this.or = false;
	this.not = false;
	this.raw = false;
};

Query$.prototype = new Query;

/**
 * @return {!string}
 */
Query.prototype.toString = function () {
	/** @type {Array.<undefined|!string>} */
	var result;
	result = [  ];
	if (this.or) {
		result.push("OR ");
	}
	if (this.not) {
		result.push("-");
	}
	if (this.raw) {
		result.push('"', this.word, '"');
	} else {
		result.push(this.word);
	}
	return result.join('');
};

/**
 * class QueryStringParser extends Object
 * @constructor
 */
function QueryStringParser() {
}

/**
 * @constructor
 */
function QueryStringParser$() {
	this.queries = [  ];
};

QueryStringParser$.prototype = new QueryStringParser;

/**
 * @param {!string} queryString
 */
QueryStringParser.prototype.parse$S = function (queryString) {
	/** @type {!boolean} */
	var nextOr;
	/** @type {!boolean} */
	var nextNot;
	/** @type {!number} */
	var currentWordStart;
	/** @type {!number} */
	var status;
	/** @type {RegExp} */
	var isSpace;
	/** @type {!number} */
	var i;
	/** @type {!string} */
	var ch;
	/** @type {!string} */
	var word;
	/** @type {Query} */
	var query;
	nextOr = false;
	nextNot = false;
	currentWordStart = 0;
	status = 0;
	isSpace = /[\s\u3000]/;
	for (i = 0; i < queryString.length; i++) {
		ch = queryString.charAt(i);
		switch (status) {
		case 0:
			if (! isSpace.test(ch)) {
				if (ch === '-') {
					nextNot = true;
				} else {
					if (ch === '"') {
						currentWordStart = i + 1;
						status = 2;
					} else {
						currentWordStart = i;
						status = 1;
					}
				}
			} else {
				nextNot = false;
			}
			break;
		case 1:
			if (isSpace.test(ch)) {
				word = queryString.slice(currentWordStart, i);
				if (word === 'OR') {
					nextOr = true;
				} else {
					query = new Query$();
					query.word = word;
					query.or = nextOr;
					query.not = nextNot;
					this.queries.push(query);
					nextOr = false;
					nextNot = false;
				}
				status = 0;
			}
			break;
		case 2:
			if (ch === '"') {
				word = queryString.slice(currentWordStart, i);
				query = new Query$();
				query.word = word;
				query.or = nextOr;
				query.not = nextNot;
				query.raw = true;
				this.queries.push(query);
				nextOr = false;
				nextNot = false;
				status = 0;
			}
			break;
		}
	}
	switch (status) {
	case 0:
		break;
	case 1:
		query = new Query$();
		word = queryString.slice(currentWordStart, queryString.length);
		if (word !== 'OR') {
			query.word = word;
			query.or = nextOr;
			query.not = nextNot;
			this.queries.push(query);
		}
		break;
	case 2:
		query = new Query$();
		query.word = queryString.slice(currentWordStart, queryString.length);
		query.or = nextOr;
		query.not = nextNot;
		query.raw = true;
		this.queries.push(query);
		break;
	}
};

/**
 * class Proposal extends Object
 * @constructor
 */
function Proposal() {
}

/**
 * @constructor
 * @param {!number} omit
 * @param {!number} expect
 */
function Proposal$II(omit, expect) {
	this.omit = omit;
	this.expect = expect;
};

Proposal$II.prototype = new Proposal;

/**
 * class Position extends Object
 * @constructor
 */
function Position() {
}

/**
 * @constructor
 * @param {!string} word
 * @param {!number} position
 * @param {!boolean} stemmed
 */
function Position$SIB(word, position, stemmed) {
	this.word = word;
	this.position = position;
	this.stemmed = stemmed;
};

Position$SIB.prototype = new Position;

/**
 * class SearchUnit extends Object
 * @constructor
 */
function SearchUnit() {
}

/**
 * @constructor
 * @param {!number} id
 */
function SearchUnit$I(id) {
	this.positions = ({  });
	this.id = id;
	this._size = 0;
	this.score = 0;
	this.startPosition = (- 1 | 0);
};

SearchUnit$I.prototype = new SearchUnit;

/**
 * @param {!string} word
 * @param {!number} position
 * @param {!boolean} stemmed
 */
SearchUnit.prototype.addPosition$SIB = function (word, position, stemmed) {
	/** @type {Position} */
	var positionObj;
	positionObj = this.positions[position + ""];
	if (! positionObj) {
		this._size++;
		this.positions[position + ""] = new Position$SIB(word, position, stemmed);
	} else {
		if (positionObj.word.length < word.length) {
			positionObj.word = word;
		}
		positionObj.stemmed = positionObj.stemmed && stemmed;
	}
};

/**
 * @param {!number} position
 * @return {Position}
 */
SearchUnit.prototype.get$I = function (position) {
	return this.positions[position + ""];
};

/**
 * @return {!number}
 */
SearchUnit.prototype.size$ = function () {
	return this._size;
};

/**
 * @param {SearchUnit} rhs
 */
SearchUnit.prototype.merge$LSearchUnit$ = function (rhs) {
	/** @type {!string} */
	var position;
	/** @type {Position} */
	var pos;
	for (position in rhs.positions) {
		pos = rhs.positions[position];
		this.addPosition$SIB(pos.word, pos.position, pos.stemmed);
	}
};

/**
 * @return {Array.<undefined|Position>}
 */
SearchUnit.prototype.getPositions$ = function () {
	var $this = this;
	/** @type {Array.<undefined|Position>} */
	var result;
	/** @type {!string} */
	var pos;
	result = [  ];
	for (pos in this.positions) {
		result.push(this.positions[pos]);
	}
	result.sort((function (a, b) {
		return a.position - b.position;
	}));
	return result;
};

/**
 * class SingleResult extends Object
 * @constructor
 */
function SingleResult() {
}

/**
 * @constructor
 */
function SingleResult$() {
	this.units = [  ];
	this.unitIds = [  ];
	this.or = false;
	this.not = false;
	this.searchWord = '';
};

SingleResult$.prototype = new SingleResult;

/**
 * @constructor
 * @param {!string} searchWord
 * @param {!boolean} or
 * @param {!boolean} not
 */
function SingleResult$SBB(searchWord, or, not) {
	this.units = [  ];
	this.unitIds = [  ];
	this.or = or;
	this.not = not;
	this.searchWord = searchWord;
};

SingleResult$SBB.prototype = new SingleResult;

/**
 * @param {!number} unitId
 * @return {SearchUnit}
 */
SingleResult.prototype.getSearchUnit$I = function (unitId) {
	/** @type {!number} */
	var existing;
	/** @type {SearchUnit} */
	var result;
	existing = this.unitIds.indexOf(unitId);
	if (existing === - 1) {
		result = new SearchUnit$I(unitId);
		this.units.push(result);
		this.unitIds.push(unitId);
	} else {
		result = this.units[existing];
	}
	return result;
};

/**
 * @param {SingleResult} rhs
 * @return {SingleResult}
 */
SingleResult.prototype.merge$LSingleResult$ = function (rhs) {
	/** @type {SingleResult} */
	var result;
	result = new SingleResult$();
	if (rhs.or) {
		this._orMerge$LSingleResult$LSingleResult$(result, rhs);
	} else {
		if (rhs.not) {
			this._notMerge$LSingleResult$LSingleResult$(result, rhs);
		} else {
			this._andMerge$LSingleResult$LSingleResult$(result, rhs);
		}
	}
	return result;
};

/**
 * @return {!number}
 */
SingleResult.prototype.size$ = function () {
	return (this.units.length | 0);
};

/**
 * @param {SingleResult} result
 * @param {SingleResult} rhs
 */
SingleResult.prototype._andMerge$LSingleResult$LSingleResult$ = function (result, rhs) {
	/** @type {!number} */
	var i;
	/** @type {undefined|!number} */
	var id;
	/** @type {SearchUnit} */
	var lhsSection;
	for (i = 0; i < this.unitIds.length; i++) {
		id = this.unitIds[i];
		if (rhs.unitIds.indexOf(id) !== - 1) {
			lhsSection = this.units[i];
			result.unitIds.push((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/search-result.jsx:168:36] null access\n                result.unitIds.push(id);\n                                    ^^\n");
				}
				return v;
			}(id)));
			result.units.push(lhsSection);
		}
	}
};

/**
 * @param {SingleResult} result
 * @param {SingleResult} rhs
 */
SingleResult.prototype._orMerge$LSingleResult$LSingleResult$ = function (result, rhs) {
	/** @type {!number} */
	var i;
	/** @type {undefined|!number} */
	var id;
	/** @type {SearchUnit} */
	var rhsSection;
	/** @type {SearchUnit} */
	var lhsSection;
	result.unitIds = this.unitIds.slice(0, this.unitIds.length);
	result.units = this.units.slice(0, this.units.length);
	for (i = 0; i < rhs.unitIds.length; i++) {
		id = rhs.unitIds[i];
		rhsSection = rhs.units[i];
		if (result.unitIds.indexOf(id) !== - 1) {
			lhsSection = result.units[result.unitIds.indexOf(id)];
			lhsSection.merge$LSearchUnit$(rhsSection);
		} else {
			result.unitIds.push((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/search-result.jsx:190:36] null access\n                result.unitIds.push(id);\n                                    ^^\n");
				}
				return v;
			}(id)));
			result.units.push(rhsSection);
		}
	}
};

/**
 * @param {SingleResult} result
 * @param {SingleResult} rhs
 */
SingleResult.prototype._notMerge$LSingleResult$LSingleResult$ = function (result, rhs) {
	/** @type {!number} */
	var i;
	/** @type {undefined|!number} */
	var id;
	/** @type {SearchUnit} */
	var lhsSection;
	for (i = 0; i < this.unitIds.length; i++) {
		id = this.unitIds[i];
		if (rhs.unitIds.indexOf(id) === - 1) {
			lhsSection = this.units[i];
			result.unitIds.push((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/search-result.jsx:204:36] null access\n                result.unitIds.push(id);\n                                    ^^\n");
				}
				return v;
			}(id)));
			result.units.push(lhsSection);
		}
	}
};

/**
 * class SearchSummary extends Object
 * @constructor
 */
function SearchSummary() {
}

/**
 * @constructor
 */
function SearchSummary$() {
	this.sourceResults = [  ];
	this.result = null;
	this.oktavia = null;
};

SearchSummary$.prototype = new SearchSummary;

/**
 * @constructor
 * @param {Oktavia} oktavia
 */
function SearchSummary$LOktavia$(oktavia) {
	this.sourceResults = [  ];
	this.result = null;
	this.oktavia = oktavia;
};

SearchSummary$LOktavia$.prototype = new SearchSummary;

/**
 * @param {SingleResult} result
 */
SearchSummary.prototype.addQuery$LSingleResult$ = function (result) {
	this.sourceResults.push(result);
};

/**
 */
SearchSummary.prototype.mergeResult$ = function () {
	this.result = this.mergeResult$ALSingleResult$(this.sourceResults);
};

/**
 * @param {Array.<undefined|SingleResult>} results
 * @return {SingleResult}
 */
SearchSummary.prototype.mergeResult$ALSingleResult$ = function (results) {
	/** @type {SingleResult} */
	var rhs;
	/** @type {!number} */
	var i;
	rhs = results[0];
	for (i = 1; i < results.length; i++) {
		rhs = rhs.merge$LSingleResult$(results[i]);
	}
	return rhs;
};

/**
 * @return {Array.<undefined|Proposal>}
 */
SearchSummary.prototype.getProposal$ = function () {
	var $this = this;
	/** @type {Array.<undefined|Proposal>} */
	var proposals;
	/** @type {!number} */
	var i;
	/** @type {Array.<undefined|SingleResult>} */
	var tmpSource;
	/** @type {!number} */
	var j;
	/** @type {SingleResult} */
	var result;
	proposals = [  ];
	for (i = 0; i < this.sourceResults.length; i++) {
		tmpSource = [  ];
		for (j = 0; j < this.sourceResults.length; j++) {
			if (i !== j) {
				tmpSource.push(this.sourceResults[j]);
			}
		}
		result = this.mergeResult$ALSingleResult$(tmpSource);
		proposals.push(new Proposal$II(i, result.size$()));
	}
	proposals.sort((function (a, b) {
		return b.expect - a.expect;
	}));
	return proposals;
};

/**
 * @return {Array.<undefined|SearchUnit>}
 */
SearchSummary.prototype.getSortedResult$ = function () {
	var $this = this;
	/** @type {Array.<undefined|SearchUnit>} */
	var result;
	result = this.result.units.slice(0, this.result.units.length);
	result.sort((function (a, b) {
		return b.score - a.score;
	}));
	return result;
};

/**
 * @return {!number}
 */
SearchSummary.prototype.size$ = function () {
	return this.result.size$();
};

/**
 * @param {SingleResult} result
 */
SearchSummary.prototype.add$LSingleResult$ = function (result) {
	this.sourceResults.push(result);
};

/**
 * class Style extends Object
 * @constructor
 */
function Style() {
}

/**
 * @constructor
 * @param {!string} mode
 */
function Style$S(mode) {
	this.styles = null;
	this.escapeHTML = false;
	switch (mode) {
	case 'console':
		this.styles = Style.console;
		break;
	case 'html':
		this.styles = Style.html;
		break;
	case 'ignore':
		this.styles = Style.ignore;
		break;
	default:
		this.styles = Style.ignore;
		break;
	}
	this.escapeHTML = mode === 'html';
};

Style$S.prototype = new Style;

/**
 * @param {!string} source
 * @return {!string}
 */
Style.prototype.convert$S = function (source) {
	/** @type {_HTMLHandler} */
	var handler;
	/** @type {SAXParser} */
	var parser;
	handler = new _HTMLHandler$HASB(this.styles, this.escapeHTML);
	parser = new SAXParser$LSAXHandler$(handler);
	parser.parse$S(source);
	return handler.result$();
};

/**
 * class Stemmer
 * @constructor
 */
function Stemmer() {
}

Stemmer.prototype.$__jsx_implements_Stemmer = true;

/**
 * @constructor
 */
function Stemmer$() {
};

Stemmer$.prototype = new Stemmer;

/**
 * class BaseStemmer extends Object
 * @constructor
 */
function BaseStemmer() {
}

$__jsx_merge_interface(BaseStemmer, Stemmer);

/**
 * @constructor
 */
function BaseStemmer$() {
	Stemmer$.call(this);
	this.current = "";
	this.cursor = 0;
	this.limit = 0;
	this.limit_backward = 0;
	this.bra = 0;
	this.ket = 0;
	this.cache = ({  });
	this.setCurrent$S("");
};

BaseStemmer$.prototype = new BaseStemmer;

/**
 * @param {!string} value
 */
BaseStemmer.prototype.setCurrent$S = function (value) {
	this.current = value;
	this.cursor = 0;
	this.limit = this.current.length;
	this.limit_backward = 0;
	this.bra = this.cursor;
	this.ket = this.limit;
};

/**
 * @return {!string}
 */
BaseStemmer.prototype.getCurrent$ = function () {
	return this.current;
};

/**
 * @param {BaseStemmer} other
 */
BaseStemmer.prototype.copy_from$LBaseStemmer$ = function (other) {
	this.current = other.current;
	this.cursor = other.cursor;
	this.limit = other.limit;
	this.limit_backward = other.limit_backward;
	this.bra = other.bra;
	this.ket = other.ket;
};

/**
 * @param {Array.<undefined|!number>} s
 * @param {!number} min
 * @param {!number} max
 * @return {!boolean}
 */
BaseStemmer.prototype.in_grouping$AIII = function (s, min, max) {
	/** @type {!number} */
	var ch;
	if (this.cursor >= this.limit) {
		return false;
	}
	ch = this.current.charCodeAt(this.cursor);
	if (ch > max || ch < min) {
		return false;
	}
	ch -= min;
	if (((function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/stemmer/base-stemmer.jsx:59:10] null access\n    if ((s[ch >>> 3] & (0x1 << (ch & 0x7))) == 0) return false;\n          ^\n");
		}
		return v;
	}(s[ch >>> 3])) & 0x1 << (ch & 0x7)) === 0) {
		return false;
	}
	this.cursor++;
	return true;
};

/**
 * @param {Array.<undefined|!number>} s
 * @param {!number} min
 * @param {!number} max
 * @return {!boolean}
 */
BaseStemmer.prototype.in_grouping_b$AIII = function (s, min, max) {
	/** @type {!number} */
	var ch;
	if (this.cursor <= this.limit_backward) {
		return false;
	}
	ch = this.current.charCodeAt(this.cursor - 1);
	if (ch > max || ch < min) {
		return false;
	}
	ch -= min;
	if (((function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/stemmer/base-stemmer.jsx:70:10] null access\n    if ((s[ch >>> 3] & (0x1 << (ch & 0x7))) == 0) return false;\n          ^\n");
		}
		return v;
	}(s[ch >>> 3])) & 0x1 << (ch & 0x7)) === 0) {
		return false;
	}
	this.cursor--;
	return true;
};

/**
 * @param {Array.<undefined|!number>} s
 * @param {!number} min
 * @param {!number} max
 * @return {!boolean}
 */
BaseStemmer.prototype.out_grouping$AIII = function (s, min, max) {
	/** @type {!number} */
	var ch;
	if (this.cursor >= this.limit) {
		return false;
	}
	ch = this.current.charCodeAt(this.cursor);
	if (ch > max || ch < min) {
		this.cursor++;
		return true;
	}
	ch -= min;
	if (((function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/stemmer/base-stemmer.jsx:84:10] null access\n    if ((s[ch >>> 3] & (0X1 << (ch & 0x7))) == 0) {\n          ^\n");
		}
		return v;
	}(s[ch >>> 3])) & 0X1 << (ch & 0x7)) === 0) {
		this.cursor++;
		return true;
	}
	return false;
};

/**
 * @param {Array.<undefined|!number>} s
 * @param {!number} min
 * @param {!number} max
 * @return {!boolean}
 */
BaseStemmer.prototype.out_grouping_b$AIII = function (s, min, max) {
	/** @type {!number} */
	var ch;
	if (this.cursor <= this.limit_backward) {
		return false;
	}
	ch = this.current.charCodeAt(this.cursor - 1);
	if (ch > max || ch < min) {
		this.cursor--;
		return true;
	}
	ch -= min;
	if (((function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/stemmer/base-stemmer.jsx:100:10] null access\n    if ((s[ch >>> 3] & (0x1 << (ch & 0x7))) == 0) {\n          ^\n");
		}
		return v;
	}(s[ch >>> 3])) & 0x1 << (ch & 0x7)) === 0) {
		this.cursor--;
		return true;
	}
	return false;
};

/**
 * @param {!number} min
 * @param {!number} max
 * @return {!boolean}
 */
BaseStemmer.prototype.in_range$II = function (min, max) {
	/** @type {!number} */
	var ch;
	if (this.cursor >= this.limit) {
		return false;
	}
	ch = this.current.charCodeAt(this.cursor);
	if (ch > max || ch < min) {
		return false;
	}
	this.cursor++;
	return true;
};

/**
 * @param {!number} min
 * @param {!number} max
 * @return {!boolean}
 */
BaseStemmer.prototype.in_range_b$II = function (min, max) {
	/** @type {!number} */
	var ch;
	if (this.cursor <= this.limit_backward) {
		return false;
	}
	ch = this.current.charCodeAt(this.cursor - 1);
	if (ch > max || ch < min) {
		return false;
	}
	this.cursor--;
	return true;
};

/**
 * @param {!number} min
 * @param {!number} max
 * @return {!boolean}
 */
BaseStemmer.prototype.out_range$II = function (min, max) {
	/** @type {!number} */
	var ch;
	if (this.cursor >= this.limit) {
		return false;
	}
	ch = this.current.charCodeAt(this.cursor);
	if (! (ch > max || ch < min)) {
		return false;
	}
	this.cursor++;
	return true;
};

/**
 * @param {!number} min
 * @param {!number} max
 * @return {!boolean}
 */
BaseStemmer.prototype.out_range_b$II = function (min, max) {
	/** @type {!number} */
	var ch;
	if (this.cursor <= this.limit_backward) {
		return false;
	}
	ch = this.current.charCodeAt(this.cursor - 1);
	if (! (ch > max || ch < min)) {
		return false;
	}
	this.cursor--;
	return true;
};

/**
 * @param {!number} s_size
 * @param {!string} s
 * @return {!boolean}
 */
BaseStemmer.prototype.eq_s$IS = function (s_size, s) {
	if (this.limit - this.cursor < s_size) {
		return false;
	}
	if (this.current.slice(this.cursor, this.cursor + s_size) !== s) {
		return false;
	}
	this.cursor += s_size;
	return true;
};

/**
 * @param {!number} s_size
 * @param {!string} s
 * @return {!boolean}
 */
BaseStemmer.prototype.eq_s_b$IS = function (s_size, s) {
	if (this.cursor - this.limit_backward < s_size) {
		return false;
	}
	if (this.current.slice(this.cursor - s_size, this.cursor) !== s) {
		return false;
	}
	this.cursor -= s_size;
	return true;
};

/**
 * @param {!string} s
 * @return {!boolean}
 */
BaseStemmer.prototype.eq_v$S = function (s) {
	return this.eq_s$IS(s.length, s);
};

/**
 * @param {!string} s
 * @return {!boolean}
 */
BaseStemmer.prototype.eq_v_b$S = function (s) {
	return this.eq_s_b$IS(s.length, s);
};

/**
 * @param {Array.<undefined|Among>} v
 * @param {!number} v_size
 * @return {!number}
 */
BaseStemmer.prototype.find_among$ALAmong$I = function (v, v_size) {
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var j;
	/** @type {!number} */
	var c;
	/** @type {!number} */
	var l;
	/** @type {!number} */
	var common_i;
	/** @type {!number} */
	var common_j;
	/** @type {!boolean} */
	var first_key_inspected;
	/** @type {!number} */
	var k;
	/** @type {!number} */
	var diff;
	/** @type {!number} */
	var common;
	/** @type {Among} */
	var w;
	/** @type {!number} */
	var i2;
	/** @type {!boolean} */
	var res;
	i = 0;
	j = v_size;
	c = this.cursor;
	l = this.limit;
	common_i = 0;
	common_j = 0;
	first_key_inspected = false;
	while (true) {
		k = i + (j - i >>> 1);
		diff = 0;
		common = (common_i < common_j ? common_i : common_j);
		w = v[k];
		for (i2 = common; i2 < w.s_size; i2++) {
			if (c + common === l) {
				diff = - 1;
				break;
			}
			diff = this.current.charCodeAt(c + common) - w.s.charCodeAt(i2);
			if (diff !== 0) {
				break;
			}
			common++;
		}
		if (diff < 0) {
			j = k;
			common_j = common;
		} else {
			i = k;
			common_i = common;
		}
		if (j - i <= 1) {
			if (i > 0) {
				break;
			}
			if (j === i) {
				break;
			}
			if (first_key_inspected) {
				break;
			}
			first_key_inspected = true;
		}
	}
	while (true) {
		w = v[i];
		if (common_i >= w.s_size) {
			this.cursor = (c + w.s_size | 0);
			if (w.method == null) {
				return w.result;
			}
			res = w.method(w.instance);
			this.cursor = (c + w.s_size | 0);
			if (res) {
				return w.result;
			}
		}
		i = w.substring_i;
		if (i < 0) {
			return 0;
		}
	}
	return (- 1 | 0);
};

/**
 * @param {Array.<undefined|Among>} v
 * @param {!number} v_size
 * @return {!number}
 */
BaseStemmer.prototype.find_among_b$ALAmong$I = function (v, v_size) {
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var j;
	/** @type {!number} */
	var c;
	/** @type {!number} */
	var lb;
	/** @type {!number} */
	var common_i;
	/** @type {!number} */
	var common_j;
	/** @type {!boolean} */
	var first_key_inspected;
	/** @type {!number} */
	var k;
	/** @type {!number} */
	var diff;
	/** @type {!number} */
	var common;
	/** @type {Among} */
	var w;
	/** @type {!number} */
	var i2;
	/** @type {!boolean} */
	var res;
	i = 0;
	j = v_size;
	c = this.cursor;
	lb = this.limit_backward;
	common_i = 0;
	common_j = 0;
	first_key_inspected = false;
	while (true) {
		k = i + (j - i >> 1);
		diff = 0;
		common = (common_i < common_j ? common_i : common_j);
		w = v[k];
		for (i2 = w.s_size - 1 - common; i2 >= 0; i2--) {
			if (c - common === lb) {
				diff = - 1;
				break;
			}
			diff = this.current.charCodeAt(c - 1 - common) - w.s.charCodeAt(i2);
			if (diff !== 0) {
				break;
			}
			common++;
		}
		if (diff < 0) {
			j = k;
			common_j = common;
		} else {
			i = k;
			common_i = common;
		}
		if (j - i <= 1) {
			if (i > 0) {
				break;
			}
			if (j === i) {
				break;
			}
			if (first_key_inspected) {
				break;
			}
			first_key_inspected = true;
		}
	}
	while (true) {
		w = v[i];
		if (common_i >= w.s_size) {
			this.cursor = (c - w.s_size | 0);
			if (w.method == null) {
				return w.result;
			}
			res = w.method(this);
			this.cursor = (c - w.s_size | 0);
			if (res) {
				return w.result;
			}
		}
		i = w.substring_i;
		if (i < 0) {
			return 0;
		}
	}
	return (- 1 | 0);
};

/**
 * @param {!number} c_bra
 * @param {!number} c_ket
 * @param {!string} s
 * @return {!number}
 */
BaseStemmer.prototype.replace_s$IIS = function (c_bra, c_ket, s) {
	/** @type {!number} */
	var adjustment;
	adjustment = s.length - (c_ket - c_bra);
	this.current = this.current.slice(0, c_bra) + s + this.current.slice(c_ket);
	this.limit += (adjustment | 0);
	if (this.cursor >= c_ket) {
		this.cursor += (adjustment | 0);
	} else {
		if (this.cursor > c_bra) {
			this.cursor = c_bra;
		}
	}
	return (adjustment | 0);
};

/**
 * @return {!boolean}
 */
BaseStemmer.prototype.slice_check$ = function () {
	if (this.bra < 0 || this.bra > this.ket || this.ket > this.limit || this.limit > this.current.length) {
		return false;
	}
	return true;
};

/**
 * @param {!string} s
 * @return {!boolean}
 */
BaseStemmer.prototype.slice_from$S = function (s) {
	/** @type {!boolean} */
	var result;
	result = false;
	if (this.slice_check$()) {
		this.replace_s$IIS(this.bra, this.ket, s);
		result = true;
	}
	return result;
};

/**
 * @return {!boolean}
 */
BaseStemmer.prototype.slice_del$ = function () {
	return this.slice_from$S("");
};

/**
 * @param {!number} c_bra
 * @param {!number} c_ket
 * @param {!string} s
 */
BaseStemmer.prototype.insert$IIS = function (c_bra, c_ket, s) {
	/** @type {!number} */
	var adjustment;
	adjustment = this.replace_s$IIS(c_bra, c_ket, s);
	if (c_bra <= this.bra) {
		this.bra += (adjustment | 0);
	}
	if (c_bra <= this.ket) {
		this.ket += (adjustment | 0);
	}
};

/**
 * @param {!string} s
 * @return {!string}
 */
BaseStemmer.prototype.slice_to$S = function (s) {
	/** @type {!string} */
	var result;
	result = '';
	if (this.slice_check$()) {
		result = this.current.slice(this.bra, this.ket);
	}
	return result;
};

/**
 * @param {!string} s
 * @return {!string}
 */
BaseStemmer.prototype.assign_to$S = function (s) {
	return this.current.slice(0, this.limit);
};

/**
 * @return {!boolean}
 */
BaseStemmer.prototype.stem$ = function () {
	return false;
};

/**
 * @param {!string} word
 * @return {!string}
 */
BaseStemmer.prototype.stemWord$S = function (word) {
	/** @type {undefined|!string} */
	var result;
	result = this.cache['.' + word];
	if (result == null) {
		this.setCurrent$S(word);
		this.stem$();
		result = this.getCurrent$();
		this.cache['.' + word] = result;
	}
	return (function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/stemmer/base-stemmer.jsx:398:15] null access\n        return result;\n               ^^^^^^\n");
		}
		return v;
	}(result));
};

/**
 * @param {Array.<undefined|!string>} words
 * @return {Array.<undefined|!string>}
 */
BaseStemmer.prototype.stemWords$AS = function (words) {
	/** @type {Array.<undefined|!string>} */
	var results;
	/** @type {!number} */
	var i;
	/** @type {undefined|!string} */
	var word;
	/** @type {undefined|!string} */
	var result;
	results = [  ];
	for (i = 0; i < words.length; i++) {
		word = words[i];
		result = this.cache['.' + (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/stemmer/base-stemmer.jsx:407:42] null access\n            var result = this.cache[\'.\' + word];\n                                          ^^^^\n");
			}
			return v;
		}(word))];
		if (result == null) {
			this.setCurrent$S((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/stemmer/base-stemmer.jsx:410:32] null access\n                this.setCurrent(word);\n                                ^^^^\n");
				}
				return v;
			}(word)));
			this.stem$();
			result = this.getCurrent$();
			this.cache['.' + (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/stemmer/base-stemmer.jsx:413:33] null access\n                this.cache[\'.\' + word] = result;\n                                 ^^^^\n");
				}
				return v;
			}(word))] = result;
		}
		results.push((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/stemmer/base-stemmer.jsx:415:25] null access\n            results.push(result);\n                         ^^^^^^\n");
			}
			return v;
		}(result)));
	}
	return results;
};

/**
 * class EnglishStemmer extends BaseStemmer
 * @constructor
 */
function EnglishStemmer() {
}

EnglishStemmer.prototype = new BaseStemmer;
/**
 * @constructor
 */
function EnglishStemmer$() {
	BaseStemmer$.call(this);
	this.B_Y_found = false;
	this.I_p2 = 0;
	this.I_p1 = 0;
};

EnglishStemmer$.prototype = new EnglishStemmer;

/**
 * @param {EnglishStemmer} other
 */
EnglishStemmer.prototype.copy_from$LEnglishStemmer$ = function (other) {
	this.B_Y_found = other.B_Y_found;
	this.I_p2 = other.I_p2;
	this.I_p1 = other.I_p1;
	BaseStemmer.prototype.copy_from$LBaseStemmer$.call(this, other);
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_prelude$ = function () {
	/** @type {!number} */
	var v_1;
	/** @type {!number} */
	var v_2;
	/** @type {!number} */
	var v_3;
	/** @type {!number} */
	var v_4;
	/** @type {!number} */
	var v_5;
	/** @type {!boolean} */
	var lab0;
	/** @type {!boolean} */
	var lab1;
	/** @type {!boolean} */
	var lab2;
	/** @type {!boolean} */
	var lab4;
	/** @type {!boolean} */
	var lab6;
	this.B_Y_found = false;
	v_1 = this.cursor;
	lab0 = true;
lab0:
	while (lab0 === true) {
		lab0 = false;
		this.bra = this.cursor;
		if (! this.eq_s$IS(1, "'")) {
			break lab0;
		}
		this.ket = this.cursor;
		if (! this.slice_del$()) {
			return false;
		}
	}
	this.cursor = v_1;
	v_2 = this.cursor;
	lab1 = true;
lab1:
	while (lab1 === true) {
		lab1 = false;
		this.bra = this.cursor;
		if (! this.eq_s$IS(1, "y")) {
			break lab1;
		}
		this.ket = this.cursor;
		if (! this.slice_from$S("Y")) {
			return false;
		}
		this.B_Y_found = true;
	}
	this.cursor = v_2;
	v_3 = this.cursor;
	lab2 = true;
lab2:
	while (lab2 === true) {
		lab2 = false;
	replab3:
		while (true) {
			v_4 = this.cursor;
			lab4 = true;
		lab4:
			while (lab4 === true) {
				lab4 = false;
			golab5:
				while (true) {
					v_5 = this.cursor;
					lab6 = true;
				lab6:
					while (lab6 === true) {
						lab6 = false;
						if (! this.in_grouping$AIII(EnglishStemmer.g_v, 97, 121)) {
							break lab6;
						}
						this.bra = this.cursor;
						if (! this.eq_s$IS(1, "y")) {
							break lab6;
						}
						this.ket = this.cursor;
						this.cursor = v_5;
						break golab5;
					}
					this.cursor = v_5;
					if (this.cursor >= this.limit) {
						break lab4;
					}
					this.cursor++;
				}
				if (! this.slice_from$S("Y")) {
					return false;
				}
				this.B_Y_found = true;
				continue replab3;
			}
			this.cursor = v_4;
			break replab3;
		}
	}
	this.cursor = v_3;
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_mark_regions$ = function () {
	/** @type {!number} */
	var v_1;
	/** @type {!number} */
	var v_2;
	/** @type {!boolean} */
	var lab0;
	/** @type {!boolean} */
	var lab1;
	/** @type {!boolean} */
	var lab2;
	/** @type {!boolean} */
	var lab4;
	/** @type {!boolean} */
	var lab6;
	/** @type {!boolean} */
	var lab8;
	/** @type {!boolean} */
	var lab10;
	this.I_p1 = this.limit;
	this.I_p2 = this.limit;
	v_1 = this.cursor;
	lab0 = true;
lab0:
	while (lab0 === true) {
		lab0 = false;
		lab1 = true;
	lab1:
		while (lab1 === true) {
			lab1 = false;
			v_2 = this.cursor;
			lab2 = true;
		lab2:
			while (lab2 === true) {
				lab2 = false;
				if (this.find_among$ALAmong$I(EnglishStemmer.a_0, 3) === 0) {
					break lab2;
				}
				break lab1;
			}
			this.cursor = v_2;
		golab3:
			while (true) {
				lab4 = true;
			lab4:
				while (lab4 === true) {
					lab4 = false;
					if (! this.in_grouping$AIII(EnglishStemmer.g_v, 97, 121)) {
						break lab4;
					}
					break golab3;
				}
				if (this.cursor >= this.limit) {
					break lab0;
				}
				this.cursor++;
			}
		golab5:
			while (true) {
				lab6 = true;
			lab6:
				while (lab6 === true) {
					lab6 = false;
					if (! this.out_grouping$AIII(EnglishStemmer.g_v, 97, 121)) {
						break lab6;
					}
					break golab5;
				}
				if (this.cursor >= this.limit) {
					break lab0;
				}
				this.cursor++;
			}
		}
		this.I_p1 = this.cursor;
	golab7:
		while (true) {
			lab8 = true;
		lab8:
			while (lab8 === true) {
				lab8 = false;
				if (! this.in_grouping$AIII(EnglishStemmer.g_v, 97, 121)) {
					break lab8;
				}
				break golab7;
			}
			if (this.cursor >= this.limit) {
				break lab0;
			}
			this.cursor++;
		}
	golab9:
		while (true) {
			lab10 = true;
		lab10:
			while (lab10 === true) {
				lab10 = false;
				if (! this.out_grouping$AIII(EnglishStemmer.g_v, 97, 121)) {
					break lab10;
				}
				break golab9;
			}
			if (this.cursor >= this.limit) {
				break lab0;
			}
			this.cursor++;
		}
		this.I_p2 = this.cursor;
	}
	this.cursor = v_1;
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_shortv$ = function () {
	/** @type {!number} */
	var v_1;
	/** @type {!boolean} */
	var lab0;
	/** @type {!boolean} */
	var lab1;
	lab0 = true;
lab0:
	while (lab0 === true) {
		lab0 = false;
		v_1 = this.limit - this.cursor;
		lab1 = true;
	lab1:
		while (lab1 === true) {
			lab1 = false;
			if (! this.out_grouping_b$AIII(EnglishStemmer.g_v_WXY, 89, 121)) {
				break lab1;
			}
			if (! this.in_grouping_b$AIII(EnglishStemmer.g_v, 97, 121)) {
				break lab1;
			}
			if (! this.out_grouping_b$AIII(EnglishStemmer.g_v, 97, 121)) {
				break lab1;
			}
			break lab0;
		}
		this.cursor = this.limit - v_1;
		if (! this.out_grouping_b$AIII(EnglishStemmer.g_v, 97, 121)) {
			return false;
		}
		if (! this.in_grouping_b$AIII(EnglishStemmer.g_v, 97, 121)) {
			return false;
		}
		if (this.cursor > this.limit_backward) {
			return false;
		}
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_R1$ = function () {
	if (! (this.I_p1 <= this.cursor)) {
		return false;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_R2$ = function () {
	if (! (this.I_p2 <= this.cursor)) {
		return false;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_Step_1a$ = function () {
	/** @type {!number} */
	var among_var;
	/** @type {!number} */
	var v_1;
	/** @type {!number} */
	var v_2;
	/** @type {!boolean} */
	var lab0;
	/** @type {!boolean} */
	var lab1;
	/** @type {!boolean} */
	var lab2;
	/** @type {!number} */
	var c;
	/** @type {!boolean} */
	var lab4;
	v_1 = this.limit - this.cursor;
	lab0 = true;
lab0:
	while (lab0 === true) {
		lab0 = false;
		this.ket = this.cursor;
		among_var = this.find_among_b$ALAmong$I(EnglishStemmer.a_1, 3);
		if (among_var === 0) {
			this.cursor = this.limit - v_1;
			break lab0;
		}
		this.bra = this.cursor;
		switch (among_var) {
		case 0:
			this.cursor = this.limit - v_1;
			break lab0;
		case 1:
			if (! this.slice_del$()) {
				return false;
			}
			break;
		}
	}
	this.ket = this.cursor;
	among_var = this.find_among_b$ALAmong$I(EnglishStemmer.a_2, 6);
	if (among_var === 0) {
		return false;
	}
	this.bra = this.cursor;
	switch (among_var) {
	case 0:
		return false;
	case 1:
		if (! this.slice_from$S("ss")) {
			return false;
		}
		break;
	case 2:
		lab1 = true;
	lab1:
		while (lab1 === true) {
			lab1 = false;
			v_2 = this.limit - this.cursor;
			lab2 = true;
		lab2:
			while (lab2 === true) {
				lab2 = false;
				c = (this.cursor - 2 | 0);
				if (this.limit_backward > c || c > this.limit) {
					break lab2;
				}
				this.cursor = c;
				if (! this.slice_from$S("i")) {
					return false;
				}
				break lab1;
			}
			this.cursor = this.limit - v_2;
			if (! this.slice_from$S("ie")) {
				return false;
			}
		}
		break;
	case 3:
		if (this.cursor <= this.limit_backward) {
			return false;
		}
		this.cursor--;
	golab3:
		while (true) {
			lab4 = true;
		lab4:
			while (lab4 === true) {
				lab4 = false;
				if (! this.in_grouping_b$AIII(EnglishStemmer.g_v, 97, 121)) {
					break lab4;
				}
				break golab3;
			}
			if (this.cursor <= this.limit_backward) {
				return false;
			}
			this.cursor--;
		}
		if (! this.slice_del$()) {
			return false;
		}
		break;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_Step_1b$ = function () {
	/** @type {!number} */
	var among_var;
	/** @type {!number} */
	var v_1;
	/** @type {!number} */
	var v_3;
	/** @type {!number} */
	var v_4;
	/** @type {!boolean} */
	var lab1;
	/** @type {!number} */
	var c;
	this.ket = this.cursor;
	among_var = this.find_among_b$ALAmong$I(EnglishStemmer.a_4, 6);
	if (among_var === 0) {
		return false;
	}
	this.bra = this.cursor;
	switch (among_var) {
	case 0:
		return false;
	case 1:
		if (! this.r_R1$()) {
			return false;
		}
		if (! this.slice_from$S("ee")) {
			return false;
		}
		break;
	case 2:
		v_1 = this.limit - this.cursor;
	golab0:
		while (true) {
			lab1 = true;
		lab1:
			while (lab1 === true) {
				lab1 = false;
				if (! this.in_grouping_b$AIII(EnglishStemmer.g_v, 97, 121)) {
					break lab1;
				}
				break golab0;
			}
			if (this.cursor <= this.limit_backward) {
				return false;
			}
			this.cursor--;
		}
		this.cursor = this.limit - v_1;
		if (! this.slice_del$()) {
			return false;
		}
		v_3 = this.limit - this.cursor;
		among_var = this.find_among_b$ALAmong$I(EnglishStemmer.a_3, 13);
		if (among_var === 0) {
			return false;
		}
		this.cursor = this.limit - v_3;
		switch (among_var) {
		case 0:
			return false;
		case 1:
			c = this.cursor;
			this.insert$IIS(this.cursor, this.cursor, "e");
			this.cursor = c;
			break;
		case 2:
			this.ket = this.cursor;
			if (this.cursor <= this.limit_backward) {
				return false;
			}
			this.cursor--;
			this.bra = this.cursor;
			if (! this.slice_del$()) {
				return false;
			}
			break;
		case 3:
			if (this.cursor !== this.I_p1) {
				return false;
			}
			v_4 = this.limit - this.cursor;
			if (! this.r_shortv$()) {
				return false;
			}
			this.cursor = this.limit - v_4;
			c = this.cursor;
			this.insert$IIS(this.cursor, this.cursor, "e");
			this.cursor = c;
			break;
		}
		break;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_Step_1c$ = function () {
	/** @type {!number} */
	var v_1;
	/** @type {!number} */
	var v_2;
	/** @type {!boolean} */
	var lab0;
	/** @type {!boolean} */
	var lab1;
	/** @type {!boolean} */
	var lab2;
	this.ket = this.cursor;
	lab0 = true;
lab0:
	while (lab0 === true) {
		lab0 = false;
		v_1 = this.limit - this.cursor;
		lab1 = true;
	lab1:
		while (lab1 === true) {
			lab1 = false;
			if (! this.eq_s_b$IS(1, "y")) {
				break lab1;
			}
			break lab0;
		}
		this.cursor = this.limit - v_1;
		if (! this.eq_s_b$IS(1, "Y")) {
			return false;
		}
	}
	this.bra = this.cursor;
	if (! this.out_grouping_b$AIII(EnglishStemmer.g_v, 97, 121)) {
		return false;
	}
	v_2 = this.limit - this.cursor;
	lab2 = true;
lab2:
	while (lab2 === true) {
		lab2 = false;
		if (this.cursor > this.limit_backward) {
			break lab2;
		}
		return false;
	}
	this.cursor = this.limit - v_2;
	if (! this.slice_from$S("i")) {
		return false;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_Step_2$ = function () {
	/** @type {!number} */
	var among_var;
	this.ket = this.cursor;
	among_var = this.find_among_b$ALAmong$I(EnglishStemmer.a_5, 24);
	if (among_var === 0) {
		return false;
	}
	this.bra = this.cursor;
	if (! this.r_R1$()) {
		return false;
	}
	switch (among_var) {
	case 0:
		return false;
	case 1:
		if (! this.slice_from$S("tion")) {
			return false;
		}
		break;
	case 2:
		if (! this.slice_from$S("ence")) {
			return false;
		}
		break;
	case 3:
		if (! this.slice_from$S("ance")) {
			return false;
		}
		break;
	case 4:
		if (! this.slice_from$S("able")) {
			return false;
		}
		break;
	case 5:
		if (! this.slice_from$S("ent")) {
			return false;
		}
		break;
	case 6:
		if (! this.slice_from$S("ize")) {
			return false;
		}
		break;
	case 7:
		if (! this.slice_from$S("ate")) {
			return false;
		}
		break;
	case 8:
		if (! this.slice_from$S("al")) {
			return false;
		}
		break;
	case 9:
		if (! this.slice_from$S("ful")) {
			return false;
		}
		break;
	case 10:
		if (! this.slice_from$S("ous")) {
			return false;
		}
		break;
	case 11:
		if (! this.slice_from$S("ive")) {
			return false;
		}
		break;
	case 12:
		if (! this.slice_from$S("ble")) {
			return false;
		}
		break;
	case 13:
		if (! this.eq_s_b$IS(1, "l")) {
			return false;
		}
		if (! this.slice_from$S("og")) {
			return false;
		}
		break;
	case 14:
		if (! this.slice_from$S("ful")) {
			return false;
		}
		break;
	case 15:
		if (! this.slice_from$S("less")) {
			return false;
		}
		break;
	case 16:
		if (! this.in_grouping_b$AIII(EnglishStemmer.g_valid_LI, 99, 116)) {
			return false;
		}
		if (! this.slice_del$()) {
			return false;
		}
		break;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_Step_3$ = function () {
	/** @type {!number} */
	var among_var;
	this.ket = this.cursor;
	among_var = this.find_among_b$ALAmong$I(EnglishStemmer.a_6, 9);
	if (among_var === 0) {
		return false;
	}
	this.bra = this.cursor;
	if (! this.r_R1$()) {
		return false;
	}
	switch (among_var) {
	case 0:
		return false;
	case 1:
		if (! this.slice_from$S("tion")) {
			return false;
		}
		break;
	case 2:
		if (! this.slice_from$S("ate")) {
			return false;
		}
		break;
	case 3:
		if (! this.slice_from$S("al")) {
			return false;
		}
		break;
	case 4:
		if (! this.slice_from$S("ic")) {
			return false;
		}
		break;
	case 5:
		if (! this.slice_del$()) {
			return false;
		}
		break;
	case 6:
		if (! this.r_R2$()) {
			return false;
		}
		if (! this.slice_del$()) {
			return false;
		}
		break;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_Step_4$ = function () {
	/** @type {!number} */
	var among_var;
	/** @type {!number} */
	var v_1;
	/** @type {!boolean} */
	var lab0;
	/** @type {!boolean} */
	var lab1;
	this.ket = this.cursor;
	among_var = this.find_among_b$ALAmong$I(EnglishStemmer.a_7, 18);
	if (among_var === 0) {
		return false;
	}
	this.bra = this.cursor;
	if (! this.r_R2$()) {
		return false;
	}
	switch (among_var) {
	case 0:
		return false;
	case 1:
		if (! this.slice_del$()) {
			return false;
		}
		break;
	case 2:
		lab0 = true;
	lab0:
		while (lab0 === true) {
			lab0 = false;
			v_1 = this.limit - this.cursor;
			lab1 = true;
		lab1:
			while (lab1 === true) {
				lab1 = false;
				if (! this.eq_s_b$IS(1, "s")) {
					break lab1;
				}
				break lab0;
			}
			this.cursor = this.limit - v_1;
			if (! this.eq_s_b$IS(1, "t")) {
				return false;
			}
		}
		if (! this.slice_del$()) {
			return false;
		}
		break;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_Step_5$ = function () {
	/** @type {!number} */
	var among_var;
	/** @type {!number} */
	var v_1;
	/** @type {!number} */
	var v_2;
	/** @type {!boolean} */
	var lab0;
	/** @type {!boolean} */
	var lab1;
	/** @type {!boolean} */
	var lab2;
	this.ket = this.cursor;
	among_var = this.find_among_b$ALAmong$I(EnglishStemmer.a_8, 2);
	if (among_var === 0) {
		return false;
	}
	this.bra = this.cursor;
	switch (among_var) {
	case 0:
		return false;
	case 1:
		lab0 = true;
	lab0:
		while (lab0 === true) {
			lab0 = false;
			v_1 = this.limit - this.cursor;
			lab1 = true;
		lab1:
			while (lab1 === true) {
				lab1 = false;
				if (! this.r_R2$()) {
					break lab1;
				}
				break lab0;
			}
			this.cursor = this.limit - v_1;
			if (! this.r_R1$()) {
				return false;
			}
			v_2 = this.limit - this.cursor;
			lab2 = true;
		lab2:
			while (lab2 === true) {
				lab2 = false;
				if (! this.r_shortv$()) {
					break lab2;
				}
				return false;
			}
			this.cursor = this.limit - v_2;
		}
		if (! this.slice_del$()) {
			return false;
		}
		break;
	case 2:
		if (! this.r_R2$()) {
			return false;
		}
		if (! this.eq_s_b$IS(1, "l")) {
			return false;
		}
		if (! this.slice_del$()) {
			return false;
		}
		break;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_exception2$ = function () {
	this.ket = this.cursor;
	if (this.find_among_b$ALAmong$I(EnglishStemmer.a_9, 8) === 0) {
		return false;
	}
	this.bra = this.cursor;
	if (this.cursor > this.limit_backward) {
		return false;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_exception1$ = function () {
	/** @type {!number} */
	var among_var;
	this.bra = this.cursor;
	among_var = this.find_among$ALAmong$I(EnglishStemmer.a_10, 18);
	if (among_var === 0) {
		return false;
	}
	this.ket = this.cursor;
	if (this.cursor < this.limit) {
		return false;
	}
	switch (among_var) {
	case 0:
		return false;
	case 1:
		if (! this.slice_from$S("ski")) {
			return false;
		}
		break;
	case 2:
		if (! this.slice_from$S("sky")) {
			return false;
		}
		break;
	case 3:
		if (! this.slice_from$S("die")) {
			return false;
		}
		break;
	case 4:
		if (! this.slice_from$S("lie")) {
			return false;
		}
		break;
	case 5:
		if (! this.slice_from$S("tie")) {
			return false;
		}
		break;
	case 6:
		if (! this.slice_from$S("idl")) {
			return false;
		}
		break;
	case 7:
		if (! this.slice_from$S("gentl")) {
			return false;
		}
		break;
	case 8:
		if (! this.slice_from$S("ugli")) {
			return false;
		}
		break;
	case 9:
		if (! this.slice_from$S("earli")) {
			return false;
		}
		break;
	case 10:
		if (! this.slice_from$S("onli")) {
			return false;
		}
		break;
	case 11:
		if (! this.slice_from$S("singl")) {
			return false;
		}
		break;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.r_postlude$ = function () {
	/** @type {!number} */
	var v_1;
	/** @type {!number} */
	var v_2;
	/** @type {!boolean} */
	var lab1;
	/** @type {!boolean} */
	var lab3;
	if (! this.B_Y_found) {
		return false;
	}
replab0:
	while (true) {
		v_1 = this.cursor;
		lab1 = true;
	lab1:
		while (lab1 === true) {
			lab1 = false;
		golab2:
			while (true) {
				v_2 = this.cursor;
				lab3 = true;
			lab3:
				while (lab3 === true) {
					lab3 = false;
					this.bra = this.cursor;
					if (! this.eq_s$IS(1, "Y")) {
						break lab3;
					}
					this.ket = this.cursor;
					this.cursor = v_2;
					break golab2;
				}
				this.cursor = v_2;
				if (this.cursor >= this.limit) {
					break lab1;
				}
				this.cursor++;
			}
			if (! this.slice_from$S("y")) {
				return false;
			}
			continue replab0;
		}
		this.cursor = v_1;
		break replab0;
	}
	return true;
};

/**
 * @return {!boolean}
 */
EnglishStemmer.prototype.stem$ = function () {
	/** @type {!number} */
	var v_1;
	/** @type {!number} */
	var v_2;
	/** @type {!number} */
	var v_3;
	/** @type {!number} */
	var v_4;
	/** @type {!number} */
	var v_5;
	/** @type {!number} */
	var v_6;
	/** @type {!number} */
	var v_7;
	/** @type {!number} */
	var v_8;
	/** @type {!number} */
	var v_9;
	/** @type {!number} */
	var v_10;
	/** @type {!number} */
	var v_11;
	/** @type {!number} */
	var v_12;
	/** @type {!number} */
	var v_13;
	/** @type {!boolean} */
	var lab0;
	/** @type {!boolean} */
	var lab1;
	/** @type {!boolean} */
	var lab2;
	/** @type {!boolean} */
	var lab3;
	/** @type {!number} */
	var c;
	/** @type {!boolean} */
	var lab4;
	/** @type {!boolean} */
	var lab5;
	/** @type {!boolean} */
	var lab6;
	/** @type {!boolean} */
	var lab7;
	/** @type {!boolean} */
	var lab8;
	/** @type {!boolean} */
	var lab9;
	/** @type {!boolean} */
	var lab10;
	/** @type {!boolean} */
	var lab11;
	/** @type {!boolean} */
	var lab12;
	/** @type {!boolean} */
	var lab13;
	/** @type {!boolean} */
	var lab14;
	/** @type {!boolean} */
	var lab15;
	lab0 = true;
lab0:
	while (lab0 === true) {
		lab0 = false;
		v_1 = this.cursor;
		lab1 = true;
	lab1:
		while (lab1 === true) {
			lab1 = false;
			if (! this.r_exception1$()) {
				break lab1;
			}
			break lab0;
		}
		this.cursor = v_1;
		lab2 = true;
	lab2:
		while (lab2 === true) {
			lab2 = false;
			v_2 = this.cursor;
			lab3 = true;
		lab3:
			while (lab3 === true) {
				lab3 = false;
				c = (this.cursor + 3 | 0);
				if (0 > c || c > this.limit) {
					break lab3;
				}
				this.cursor = c;
				break lab2;
			}
			this.cursor = v_2;
			break lab0;
		}
		this.cursor = v_1;
		v_3 = this.cursor;
		lab4 = true;
	lab4:
		while (lab4 === true) {
			lab4 = false;
			if (! this.r_prelude$()) {
				break lab4;
			}
		}
		this.cursor = v_3;
		v_4 = this.cursor;
		lab5 = true;
	lab5:
		while (lab5 === true) {
			lab5 = false;
			if (! this.r_mark_regions$()) {
				break lab5;
			}
		}
		this.cursor = v_4;
		this.limit_backward = this.cursor;
		this.cursor = this.limit;
		v_5 = this.limit - this.cursor;
		lab6 = true;
	lab6:
		while (lab6 === true) {
			lab6 = false;
			if (! this.r_Step_1a$()) {
				break lab6;
			}
		}
		this.cursor = this.limit - v_5;
		lab7 = true;
	lab7:
		while (lab7 === true) {
			lab7 = false;
			v_6 = this.limit - this.cursor;
			lab8 = true;
		lab8:
			while (lab8 === true) {
				lab8 = false;
				if (! this.r_exception2$()) {
					break lab8;
				}
				break lab7;
			}
			this.cursor = this.limit - v_6;
			v_7 = this.limit - this.cursor;
			lab9 = true;
		lab9:
			while (lab9 === true) {
				lab9 = false;
				if (! this.r_Step_1b$()) {
					break lab9;
				}
			}
			this.cursor = this.limit - v_7;
			v_8 = this.limit - this.cursor;
			lab10 = true;
		lab10:
			while (lab10 === true) {
				lab10 = false;
				if (! this.r_Step_1c$()) {
					break lab10;
				}
			}
			this.cursor = this.limit - v_8;
			v_9 = this.limit - this.cursor;
			lab11 = true;
		lab11:
			while (lab11 === true) {
				lab11 = false;
				if (! this.r_Step_2$()) {
					break lab11;
				}
			}
			this.cursor = this.limit - v_9;
			v_10 = this.limit - this.cursor;
			lab12 = true;
		lab12:
			while (lab12 === true) {
				lab12 = false;
				if (! this.r_Step_3$()) {
					break lab12;
				}
			}
			this.cursor = this.limit - v_10;
			v_11 = this.limit - this.cursor;
			lab13 = true;
		lab13:
			while (lab13 === true) {
				lab13 = false;
				if (! this.r_Step_4$()) {
					break lab13;
				}
			}
			this.cursor = this.limit - v_11;
			v_12 = this.limit - this.cursor;
			lab14 = true;
		lab14:
			while (lab14 === true) {
				lab14 = false;
				if (! this.r_Step_5$()) {
					break lab14;
				}
			}
			this.cursor = this.limit - v_12;
		}
		this.cursor = this.limit_backward;
		v_13 = this.cursor;
		lab15 = true;
	lab15:
		while (lab15 === true) {
			lab15 = false;
			if (! this.r_postlude$()) {
				break lab15;
			}
		}
		this.cursor = v_13;
	}
	return true;
};

/**
 * @param {*} o
 * @return {!boolean}
 */
EnglishStemmer.prototype.equals$X = function (o) {
	return o instanceof EnglishStemmer;
};

/**
 * @return {!number}
 */
EnglishStemmer.prototype.hashCode$ = function () {
	/** @type {!string} */
	var classname;
	/** @type {!number} */
	var hash;
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var char;
	classname = "EnglishStemmer";
	hash = 0;
	if (classname.length === 0) {
		return (hash | 0);
	}
	for (i = 0; i < classname.length; i++) {
		char = classname.charCodeAt(i);
		hash = (hash << 5) - hash + char;
		hash = hash & hash;
	}
	return (hash | 0);
};

/**
 * class Among extends Object
 * @constructor
 */
function Among() {
}

/**
 * @constructor
 * @param {!string} s
 * @param {!number} substring_i
 * @param {!number} result
 */
function Among$SII(s, substring_i, result) {
	this.s_size = s.length;
	this.s = s;
	this.substring_i = substring_i;
	this.result = result;
	this.method = null;
	this.instance = null;
};

Among$SII.prototype = new Among;

/**
 * @constructor
 * @param {!string} s
 * @param {!number} substring_i
 * @param {!number} result
 * @param {*} method
 * @param {BaseStemmer} instance
 */
function Among$SIIF$LBaseStemmer$B$LBaseStemmer$(s, substring_i, result, method, instance) {
	this.s_size = s.length;
	this.s = s;
	this.substring_i = substring_i;
	this.result = result;
	this.method = method;
	this.instance = instance;
};

Among$SIIF$LBaseStemmer$B$LBaseStemmer$.prototype = new Among;

/**
 * class Metadata extends Object
 * @constructor
 */
function Metadata() {
}

/**
 * @constructor
 * @param {Oktavia} parent
 */
function Metadata$LOktavia$(parent) {
	this._parent = parent;
	this._bitVector = new BitVector$();
};

Metadata$LOktavia$.prototype = new Metadata;

/**
 * @return {!number}
 */
Metadata.prototype._size$ = function () {
	return this._bitVector.rank$I(this._bitVector.size$());
};

/**
 * @param {!number} index
 * @return {!string}
 */
Metadata.prototype.getContent$I = function (index) {
	/** @type {!number} */
	var startPosition;
	/** @type {!number} */
	var length;
	if (index < 0 || this._size$() <= index) {
		throw new Error("Section.getContent() : range error " + (index + ""));
	}
	startPosition = 0;
	if (index > 0) {
		startPosition = this._bitVector.select$I(index - 1) + 1;
	}
	console.log(startPosition);
	length = this._bitVector.select$I(index) - startPosition + 1;
	console.log(length);
	return this._parent._getSubstring$II(startPosition, length);
};

/**
 * @param {!number} index
 * @return {!number}
 */
Metadata.prototype.getStartPosition$I = function (index) {
	/** @type {!number} */
	var startPosition;
	if (index < 0 || this._size$() <= index) {
		throw new Error("Section.getContent() : range error " + (index + ""));
	}
	startPosition = 0;
	if (index > 0) {
		startPosition = this._bitVector.select$I(index - 1) + 1;
	}
	return (startPosition | 0);
};

/**
 * @param {SingleResult} result
 * @param {Array.<undefined|!number>} positions
 * @param {!string} word
 * @param {!boolean} stemmed
 */
Metadata.prototype.grouping$LSingleResult$AISB = function (result, positions, word, stemmed) {
};

/**
 * @param {!number} index
 * @return {!string}
 */
Metadata.prototype.getInformation$I = function (index) {
	return '';
};

/**
 */
Metadata.prototype._build$ = function () {
	this._bitVector.build$();
};

/**
 * @param {!string} name
 * @param {!string} data
 * @param {!number} offset
 * @return {!number}
 */
Metadata.prototype._load$SSI = function (name, data, offset) {
	offset = this._bitVector.load$SI(data, offset);
	this._parent._metadataLabels.push(name);
	this._parent._metadatas[name] = this;
	return offset;
};

/**
 * @return {!string}
 */
Metadata.prototype._dump$ = function () {
	return this._bitVector.dump$();
};

/**
 * @param {CompressionReport} report
 * @return {!string}
 */
Metadata.prototype._dump$LCompressionReport$ = function (report) {
	return this._bitVector.dump$LCompressionReport$(report);
};

/**
 * class Section extends Metadata
 * @constructor
 */
function Section() {
}

Section.prototype = new Metadata;
/**
 * @constructor
 * @param {Oktavia} parent
 */
function Section$LOktavia$(parent) {
	Metadata$LOktavia$.call(this, parent);
	this._names = [  ];
};

Section$LOktavia$.prototype = new Section;

/**
 * @param {!string} name
 */
Section.prototype.setTail$S = function (name) {
	this.setTail$SI(name, this._parent.contentSize$());
};

/**
 * @param {!string} name
 * @param {!number} index
 */
Section.prototype.setTail$SI = function (name, index) {
	this._names.push(name);
	this._bitVector.set$I(index - 1);
};

/**
 * @return {!number}
 */
Section.prototype.size$ = function () {
	return (this._names.length | 0);
};

/**
 * @param {!number} position
 * @return {!number}
 */
Section.prototype.getSectionIndex$I = function (position) {
	if (position < 0 || this._bitVector.size$() <= position) {
		throw new Error("Section.getSectionIndex() : range error " + (position + ""));
	}
	return this._bitVector.rank$I(position);
};

/**
 * @param {!number} index
 * @return {!string}
 */
Section.prototype.getName$I = function (index) {
	if (index < 0 || this.size$() <= index) {
		throw new Error("Section.getName() : range error");
	}
	return (function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/metadata.jsx:129:26] null access\n        return this._names[index];\n                          ^\n");
		}
		return v;
	}(this._names[index]));
};

/**
 * @param {SingleResult} result
 * @param {Array.<undefined|!number>} positions
 * @param {!string} word
 * @param {!boolean} stemmed
 */
Section.prototype.grouping$LSingleResult$AISB = function (result, positions, word, stemmed) {
	/** @type {!number} */
	var i;
	/** @type {undefined|!number} */
	var position;
	/** @type {!number} */
	var index;
	/** @type {SearchUnit} */
	var unit;
	for (i = 0; i < positions.length; i++) {
		position = positions[i];
		index = this.getSectionIndex$I((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/metadata.jsx:137:45] null access\n            var index = this.getSectionIndex(position);\n                                             ^^^^^^^^\n");
			}
			return v;
		}(position)));
		unit = result.getSearchUnit$I(index);
		if (unit.startPosition < 0) {
			unit.startPosition = this.getStartPosition$I(index);
		}
		unit.addPosition$SIB(word, (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/metadata.jsx:143:35] null access\n            unit.addPosition(word, position - unit.startPosition, stemmed);\n                                   ^^^^^^^^\n");
			}
			return v;
		}(position)) - unit.startPosition, stemmed);
	}
};

/**
 * @param {!number} index
 * @return {!string}
 */
Section.prototype.getInformation$I = function (index) {
	return this.getName$I(index);
};

/**
 * @param {Oktavia} parent
 * @param {!string} name
 * @param {!string} data
 * @param {!number} offset
 * @return {!number}
 */
Section._load$LOktavia$SSI = function (parent, name, data, offset) {
	/** @type {LoadedStringListResult} */
	var strs;
	/** @type {Section} */
	var section;
	strs = Binary$loadStringList$SI(data, offset);
	section = new Section$LOktavia$(parent);
	section._names = strs.result;
	return section._load$SSI(name, data, strs.offset);
};

var Section$_load$LOktavia$SSI = Section._load$LOktavia$SSI;

/**
 * @return {!string}
 */
Section.prototype._dump$ = function () {
	return [ Binary$dump16bitNumber$I(0), Binary$dumpStringList$AS(this._names), Metadata.prototype._dump$.call(this) ].join('');
};

/**
 * @param {CompressionReport} report
 * @return {!string}
 */
Section.prototype._dump$LCompressionReport$ = function (report) {
	report.add$II(1, 1);
	return [ Binary$dump16bitNumber$I(0), Binary$dumpStringList$ASLCompressionReport$(this._names, report), Metadata.prototype._dump$LCompressionReport$.call(this, report) ].join('');
};

/**
 * class Splitter extends Metadata
 * @constructor
 */
function Splitter() {
}

Splitter.prototype = new Metadata;
/**
 * @constructor
 * @param {Oktavia} parent
 */
function Splitter$LOktavia$(parent) {
	Metadata$LOktavia$.call(this, parent);
	this.name = null;
};

Splitter$LOktavia$.prototype = new Splitter;

/**
 * @constructor
 * @param {Oktavia} parent
 * @param {!string} name
 */
function Splitter$LOktavia$S(parent, name) {
	Metadata$LOktavia$.call(this, parent);
	this.name = name;
};

Splitter$LOktavia$S.prototype = new Splitter;

/**
 * @return {!number}
 */
Splitter.prototype.size$ = function () {
	return this._size$();
};

/**
 */
Splitter.prototype.split$ = function () {
	this.split$I(this._parent.contentSize$());
};

/**
 * @param {!number} index
 */
Splitter.prototype.split$I = function (index) {
	this._bitVector.set$I(index - 1);
};

/**
 * @param {!number} position
 * @return {!number}
 */
Splitter.prototype.getIndex$I = function (position) {
	if (position < 0 || this._bitVector.size$() <= position) {
		throw new Error("Section.getSectionIndex() : range error");
	}
	return this._bitVector.rank$I(position);
};

/**
 * @param {SingleResult} result
 * @param {Array.<undefined|!number>} positions
 * @param {!string} word
 * @param {!boolean} stemmed
 */
Splitter.prototype.grouping$LSingleResult$AISB = function (result, positions, word, stemmed) {
};

/**
 * @param {!number} index
 * @return {!string}
 */
Splitter.prototype.getInformation$I = function (index) {
	if (this.name != null) {
		return (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/metadata.jsx:221:23] null access\n            return this.name + ((index + 1) as string);\n                       ^\n");
			}
			return v;
		}(this.name)) + (index + 1 + "");
	}
	return '';
};

/**
 * @param {Oktavia} parent
 * @param {!string} name
 * @param {!string} data
 * @param {!number} offset
 * @return {!number}
 */
Splitter._load$LOktavia$SSI = function (parent, name, data, offset) {
	/** @type {Splitter} */
	var section;
	section = new Splitter$LOktavia$(parent);
	return section._load$SSI(name, data, offset);
};

var Splitter$_load$LOktavia$SSI = Splitter._load$LOktavia$SSI;

/**
 * @return {!string}
 */
Splitter.prototype._dump$ = function () {
	return [ Binary$dump16bitNumber$I(1), Metadata.prototype._dump$.call(this) ].join('');
};

/**
 * @param {CompressionReport} report
 * @return {!string}
 */
Splitter.prototype._dump$LCompressionReport$ = function (report) {
	report.add$II(1, 1);
	return [ Binary$dump16bitNumber$I(1), Metadata.prototype._dump$LCompressionReport$.call(this, report) ].join('');
};

/**
 * class Table extends Metadata
 * @constructor
 */
function Table() {
}

Table.prototype = new Metadata;
/**
 * @constructor
 * @param {Oktavia} parent
 * @param {Array.<undefined|!string>} headers
 */
function Table$LOktavia$AS(parent, headers) {
	Metadata$LOktavia$.call(this, parent);
	this._headers = headers;
	this._columnTails = new BitVector$();
};

Table$LOktavia$AS.prototype = new Table;

/**
 * @return {!number}
 */
Table.prototype.rowSize$ = function () {
	return this._size$();
};

/**
 * @return {!number}
 */
Table.prototype.columnSize$ = function () {
	return (this._headers.length | 0);
};

/**
 */
Table.prototype.setColumnTail$ = function () {
	/** @type {!number} */
	var index;
	index = this._parent.contentSize$();
	this._parent.addEndOfBlock$();
	this._columnTails.set$I(index - 1);
};

/**
 */
Table.prototype.setRowTail$ = function () {
	/** @type {!number} */
	var index;
	index = this._parent.contentSize$();
	this._bitVector.set$I(index - 1);
};

/**
 * @param {!number} position
 * @return {Array.<undefined|!number>}
 */
Table.prototype.getCell$I = function (position) {
	/** @type {!number} */
	var row;
	/** @type {!number} */
	var currentColumn;
	/** @type {!number} */
	var lastRowColumn;
	/** @type {!number} */
	var startPosition;
	/** @type {Array.<undefined|!number>} */
	var result;
	if (position < 0 || this._bitVector.size$() <= position) {
		throw new Error("Section.getSectionIndex() : range error " + (position + ""));
	}
	row = this._bitVector.rank$I(position);
	currentColumn = this._columnTails.rank$I(position);
	lastRowColumn = 0;
	if (row > 0) {
		startPosition = this._bitVector.select$I(row - 1) + 1;
		lastRowColumn = this._columnTails.rank$I(startPosition);
	}
	result = [ row, currentColumn - lastRowColumn ];
	return result;
};

/**
 * @param {!number} rowIndex
 * @return {Object.<string, undefined|!string>}
 */
Table.prototype.getRowContent$I = function (rowIndex) {
	/** @type {!string} */
	var content;
	/** @type {Array.<undefined|!string>} */
	var values;
	/** @type {Object.<string, undefined|!string>} */
	var result;
	/** @type {!number} */
	var i;
	content = this.getContent$I(rowIndex);
	values = content.split(Oktavia.eob, this._headers.length);
	result = ({  });
	for (i in this._headers) {
		if (i < values.length) {
			result[this._headers[i]] = values[i];
		} else {
			result[this._headers[i]] = '';
		}
	}
	return result;
};

/**
 * @param {SingleResult} result
 * @param {Array.<undefined|!number>} positions
 * @param {!string} word
 * @param {!boolean} stemmed
 */
Table.prototype.grouping$LSingleResult$AISB = function (result, positions, word, stemmed) {
};

/**
 * @param {!number} index
 * @return {!string}
 */
Table.prototype.getInformation$I = function (index) {
	return '';
};

/**
 */
Table.prototype._build$ = function () {
	this._bitVector.build$();
	this._columnTails.build$();
};

/**
 * @param {Oktavia} parent
 * @param {!string} name
 * @param {!string} data
 * @param {!number} offset
 * @return {!number}
 */
Table._load$LOktavia$SSI = function (parent, name, data, offset) {
	/** @type {LoadedStringListResult} */
	var strs;
	/** @type {Table} */
	var table;
	strs = Binary$loadStringList$SI(data, offset);
	table = new Table$LOktavia$AS(parent, strs.result);
	offset = table._load$SSI(name, data, strs.offset);
	return table._columnTails.load$SI(data, offset);
};

var Table$_load$LOktavia$SSI = Table._load$LOktavia$SSI;

/**
 * @return {!string}
 */
Table.prototype._dump$ = function () {
	return [ Binary$dump16bitNumber$I(2), Binary$dumpStringList$AS(this._headers), Metadata.prototype._dump$.call(this), this._columnTails.dump$() ].join('');
};

/**
 * @param {CompressionReport} report
 * @return {!string}
 */
Table.prototype._dump$LCompressionReport$ = function (report) {
	report.add$II(1, 1);
	return [ Binary$dump16bitNumber$I(2), Binary$dumpStringList$ASLCompressionReport$(this._headers, report), Metadata.prototype._dump$LCompressionReport$.call(this, report), this._columnTails.dump$LCompressionReport$(report) ].join('');
};

/**
 * class Block extends Metadata
 * @constructor
 */
function Block() {
}

Block.prototype = new Metadata;
/**
 * @constructor
 * @param {Oktavia} parent
 */
function Block$LOktavia$(parent) {
	Metadata$LOktavia$.call(this, parent);
	this._names = [  ];
	this._start = false;
};

Block$LOktavia$.prototype = new Block;

/**
 * @param {!string} blockName
 */
Block.prototype.startBlock$S = function (blockName) {
	this.startBlock$SI(blockName, this._parent.contentSize$());
};

/**
 * @param {!string} blockName
 * @param {!number} index
 */
Block.prototype.startBlock$SI = function (blockName, index) {
	if (this._start) {
		throw new Error('Splitter `' + (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/metadata.jsx:380:54] null access\n            throw new Error(\'Splitter `\' + this._names[this._names.length - 1] + \'` is not closed\');\n                                                      ^\n");
			}
			return v;
		}(this._names[this._names.length - 1])) + '` is not closed');
	}
	this._start = true;
	this._names.push(blockName);
	this._bitVector.set$I(index - 1);
};

/**
 */
Block.prototype.endBlock$ = function () {
	this.endBlock$I(this._parent.contentSize$());
};

/**
 * @param {!number} index
 */
Block.prototype.endBlock$I = function (index) {
	if (! this._start) {
		throw new Error('Splitter is not started');
	}
	this._start = false;
	this._bitVector.set$I(index - 1);
};

/**
 * @return {!number}
 */
Block.prototype.size$ = function () {
	return (this._names.length | 0);
};

/**
 * @param {!number} position
 * @return {!number}
 */
Block.prototype.blockIndex$I = function (position) {
	/** @type {!number} */
	var result;
	if (position < 0 || this._parent._fmindex.size$() - 1 <= position) {
		throw new Error("Block.blockIndex() : range error " + (position + ""));
	}
	if (position >= this._bitVector.size$()) {
		position = (this._bitVector.size$() - 1 | 0);
		result = (this._bitVector.rank$I(position) + 1 | 0);
	} else {
		result = this._bitVector.rank$I(position);
	}
	return result;
};

/**
 * @param {!number} position
 * @return {!boolean}
 */
Block.prototype.inBlock$I = function (position) {
	/** @type {!number} */
	var blockIndex;
	blockIndex = this.blockIndex$I(position);
	return blockIndex % 2 !== 0;
};

/**
 * @param {!number} position
 * @return {!string}
 */
Block.prototype.getBlockContent$I = function (position) {
	/** @type {!number} */
	var blockIndex;
	/** @type {!string} */
	var result;
	blockIndex = this.blockIndex$I(position);
	if (blockIndex % 2 !== 0) {
		result = this.getContent$I(blockIndex);
	} else {
		result = '';
	}
	return result;
};

/**
 * @param {!number} position
 * @return {!string}
 */
Block.prototype.getBlockName$I = function (position) {
	/** @type {!number} */
	var blockIndex;
	/** @type {!string} */
	var result;
	blockIndex = this.blockIndex$I(position);
	if (blockIndex % 2 !== 0) {
		result = (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/metadata.jsx:453:32] null access\n            result = this._names[blockIndex >>> 1];\n                                ^\n");
			}
			return v;
		}(this._names[blockIndex >>> 1]));
	} else {
		result = '';
	}
	return result;
};

/**
 * @param {SingleResult} result
 * @param {Array.<undefined|!number>} positions
 * @param {!string} word
 * @param {!boolean} stemmed
 */
Block.prototype.grouping$LSingleResult$AISB = function (result, positions, word, stemmed) {
};

/**
 * @param {!number} index
 * @return {!string}
 */
Block.prototype.getInformation$I = function (index) {
	return '';
};

/**
 * @param {Oktavia} parent
 * @param {!string} name
 * @param {!string} data
 * @param {!number} offset
 * @return {!number}
 */
Block._load$LOktavia$SSI = function (parent, name, data, offset) {
	/** @type {LoadedStringListResult} */
	var strs;
	/** @type {Block} */
	var block;
	strs = Binary$loadStringList$SI(data, offset);
	block = new Block$LOktavia$(parent);
	block._names = strs.result;
	return block._load$SSI(name, data, strs.offset);
};

var Block$_load$LOktavia$SSI = Block._load$LOktavia$SSI;

/**
 * @return {!string}
 */
Block.prototype._dump$ = function () {
	return [ Binary$dump16bitNumber$I(3), Binary$dumpStringList$AS(this._names), Metadata.prototype._dump$.call(this) ].join('');
};

/**
 * @param {CompressionReport} report
 * @return {!string}
 */
Block.prototype._dump$LCompressionReport$ = function (report) {
	report.add$II(1, 1);
	return [ Binary$dump16bitNumber$I(3), Binary$dumpStringList$ASLCompressionReport$(this._names, report), Metadata.prototype._dump$LCompressionReport$.call(this, report) ].join('');
};

/**
 * class FMIndex extends Object
 * @constructor
 */
function FMIndex() {
}

/**
 * @constructor
 */
function FMIndex$() {
	this._ssize = 0;
	(this._ddic = 0, this._head = 0);
	this._substr = "";
	this._sv = new WaveletMatrix$();
	this._posdic = [  ];
	this._idic = [  ];
	this._rlt = [  ];
	this._rlt.length = 65536;
};

FMIndex$.prototype = new FMIndex;

/**
 */
FMIndex.prototype.clear$ = function () {
	this._sv.clear$();
	this._posdic.length = 0;
	this._idic.length = 0;
	this._ddic = 0;
	this._head = 0;
	this._substr = "";
};

/**
 * @return {!number}
 */
FMIndex.prototype.size$ = function () {
	return this._sv.size$();
};

/**
 * @return {!number}
 */
FMIndex.prototype.contentSize$ = function () {
	return this._substr.length;
};

/**
 * @param {!string} key
 * @return {!number}
 */
FMIndex.prototype.getRows$S = function (key) {
	/** @type {Array.<undefined|!number>} */
	var pos;
	pos = [  ];
	return this.getRows$SAI(key, pos);
};

/**
 * @param {!string} key
 * @param {Array.<undefined|!number>} pos
 * @return {!number}
 */
FMIndex.prototype.getRows$SAI = function (key, pos) {
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var code;
	/** @type {!number} */
	var first;
	/** @type {undefined|!number} */
	var last;
	/** @type {!number} */
	var c;
	i = key.length - 1;
	code = key.charCodeAt(i);
	first = (function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/fm-index.jsx:67:29] null access\n        var first = this._rlt[code] + 1;\n                             ^\n");
		}
		return v;
	}(this._rlt[code])) + 1;
	last = this._rlt[code + 1];
	while (first <= (function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/fm-index.jsx:69:24] null access\n        while (first <= last)\n                        ^^^^\n");
		}
		return v;
	}(last))) {
		if (i === 0) {
			pos[0] = (-- first | 0);
			pos[1] = -- last;
			return ((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/fm-index.jsx:75:24] null access\n                return (last - first  + 1);\n                        ^^^^\n");
				}
				return v;
			}(last)) - first + 1 | 0);
		}
		i--;
		c = key.charCodeAt(i);
		first = (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/fm-index.jsx:79:29] null access\n            first = this._rlt[c] + this._sv.rank(first - 1, c) + 1;\n                             ^\n");
			}
			return v;
		}(this._rlt[c])) + this._sv.rank$II(first - 1, c) + 1;
		last = (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/fm-index.jsx:80:29] null access\n            last  = this._rlt[c] + this._sv.rank(last,      c);\n                             ^\n");
			}
			return v;
		}(this._rlt[c])) + this._sv.rank$II((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/fm-index.jsx:80:49] null access\n            last  = this._rlt[c] + this._sv.rank(last,      c);\n                                                 ^^^^\n");
			}
			return v;
		}(last)), c);
	}
	return 0;
};

/**
 * @param {!number} i
 * @return {!number}
 */
FMIndex.prototype.getPosition$I = function (i) {
	/** @type {!number} */
	var pos;
	/** @type {!number} */
	var c;
	if (i >= this.size$()) {
		throw new Error("FMIndex.getPosition() : range error");
	}
	pos = 0;
	while (i !== this._head) {
		if (i % this._ddic === 0) {
			pos += (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/fm-index.jsx:96:36] null access\n                pos += (this._posdic[i / this._ddic] + 1);\n                                    ^\n");
				}
				return v;
			}(this._posdic[i / this._ddic])) + 1;
			break;
		}
		c = this._sv.get$I(i);
		i = (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/fm-index.jsx:100:25] null access\n            i = this._rlt[c] + this._sv.rank(i, c); //LF\n                         ^\n");
			}
			return v;
		}(this._rlt[c])) + this._sv.rank$II(i, c);
		pos++;
	}
	return (pos % this.size$() | 0);
};

/**
 * @param {!number} pos
 * @param {!number} len
 * @return {!string}
 */
FMIndex.prototype.getSubstring$II = function (pos, len) {
	/** @type {!number} */
	var pos_end;
	/** @type {!number} */
	var pos_tmp;
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var pos_idic;
	/** @type {!string} */
	var substr;
	/** @type {!number} */
	var c;
	if (pos >= this.size$()) {
		throw new Error("FMIndex.getSubstring() : range error");
	}
	pos_end = Math.min(pos + len, this.size$());
	pos_tmp = this.size$() - 1;
	i = this._head;
	pos_idic = Math.floor((pos_end + this._ddic - 2) / this._ddic);
	if (pos_idic < this._idic.length) {
		pos_tmp = pos_idic * this._ddic;
		i = (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/fm-index.jsx:119:32] null access\n            i       = this._idic[pos_idic];\n                                ^\n");
			}
			return v;
		}(this._idic[pos_idic]));
	}
	substr = "";
	while (pos_tmp >= pos) {
		c = this._sv.get$I(i);
		i = (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/fm-index.jsx:126:25] null access\n            i = this._rlt[c] + this._sv.rank(i, c); //LF\n                         ^\n");
			}
			return v;
		}(this._rlt[c])) + this._sv.rank$II(i, c);
		if (pos_tmp < pos_end) {
			substr = String.fromCharCode(c) + substr;
		}
		if (pos_tmp === 0) {
			break;
		}
		pos_tmp--;
	}
	return substr;
};

/**
 */
FMIndex.prototype.build$ = function () {
	this.build$SIIB(String.fromCharCode(0), 65535, 20, false);
};

/**
 * @param {!string} end_marker
 * @param {!number} ddic
 * @param {!boolean} verbose
 */
FMIndex.prototype.build$SIB = function (end_marker, ddic, verbose) {
	this.build$SIIB(end_marker, 65535, ddic, verbose);
};

/**
 * @param {!string} end_marker
 * @param {!number} maxChar
 * @param {!number} ddic
 * @param {!boolean} verbose
 */
FMIndex.prototype.build$SIIB = function (end_marker, maxChar, ddic, verbose) {
	/** @type {BurrowsWheelerTransform} */
	var b;
	/** @type {!string} */
	var s;
	/** @type {!number} */
	var c;
	if (verbose) {
		console.time("building burrows-wheeler transform");
	}
	this._substr += end_marker;
	b = new BurrowsWheelerTransform$();
	b.build$S(this._substr);
	s = b.get$();
	this._ssize = s.length;
	this._head = b.head$();
	b.clear$();
	this._substr = "";
	if (verbose) {
		console.timeEnd("building burrows-wheeler transform");
	}
	if (verbose) {
		console.time("building wavelet matrix");
	}
	this._sv.setMaxCharCode$I(maxChar);
	if (verbose) {
		console.log("  maxCharCode: ", maxChar);
		console.log("  bitSize: ", this._sv.bitsize$());
	}
	this._sv.build$S(s);
	if (verbose) {
		console.timeEnd("building wavelet matrix");
	}
	if (verbose) {
		console.time("caching rank less than");
	}
	for (c = 0; c < maxChar; c++) {
		this._rlt[c] = this._sv.rank_less_than$II(this._sv.size$(), c);
	}
	if (verbose) {
		console.timeEnd("caching rank less than");
	}
	this._ddic = ddic;
	if (verbose) {
		console.time("building dictionaries");
	}
	this._buildDictionaries$();
	if (verbose) {
		console.timeEnd("building dictionaries");
		console.log('');
	}
};

/**
 */
FMIndex.prototype._buildDictionaries$ = function () {
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var pos;
	/** @type {!number} */
	var c;
	for (i = 0; i < this._ssize / this._ddic + 1; i++) {
		this._posdic.push(0);
		this._idic.push(0);
	}
	i = this._head;
	pos = this.size$() - 1;
	do {
		if (i % this._ddic === 0) {
			this._posdic[Math.floor(i / this._ddic)] = (pos | 0);
		}
		if (pos % this._ddic === 0) {
			this._idic[Math.floor(pos / this._ddic)] = (i | 0);
		}
		c = this._sv.get$I(i);
		i = (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/fm-index.jsx:228:25] null access\n            i = this._rlt[c] + this._sv.rank(i, c); //LF\n                         ^\n");
			}
			return v;
		}(this._rlt[c])) + this._sv.rank$II(i, c);
		pos--;
	} while (i !== this._head);
};

/**
 * @param {!string} doc
 */
FMIndex.prototype.push$S = function (doc) {
	if (doc.length <= 0) {
		throw new Error("FMIndex::push(): empty string");
	}
	this._substr += doc;
};

/**
 * @param {!string} keyword
 * @return {Array.<undefined|!number>}
 */
FMIndex.prototype.search$S = function (keyword) {
	/** @type {Object.<string, undefined|!number>} */
	var result_map;
	/** @type {Array.<undefined|!number>} */
	var result;
	/** @type {Array.<undefined|!number>} */
	var position;
	/** @type {!number} */
	var rows;
	/** @type {undefined|!number} */
	var first;
	/** @type {undefined|!number} */
	var last;
	/** @type {undefined|!number} */
	var i;
	result_map = ({  });
	result = [  ];
	position = [  ];
	rows = this.getRows$SAI(keyword, position);
	if (rows > 0) {
		first = position[0];
		last = position[1];
		for (i = first; (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/fm-index.jsx:252:32] null access\n            for (var i = first; i <= last; i++)\n                                ^\n");
			}
			return v;
		}(i)) <= (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/fm-index.jsx:252:37] null access\n            for (var i = first; i <= last; i++)\n                                     ^^^^\n");
			}
			return v;
		}(last)); i++) {
			result.push(this.getPosition$I((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/fm-index.jsx:254:45] null access\n                result.push(this.getPosition(i));\n                                             ^\n");
				}
				return v;
			}(i))));
		}
	}
	return result;
};

/**
 * @return {!string}
 */
FMIndex.prototype.dump$ = function () {
	return this.dump$B(false);
};

/**
 * @param {!boolean} verbose
 * @return {!string}
 */
FMIndex.prototype.dump$B = function (verbose) {
	/** @type {Array.<undefined|!string>} */
	var contents;
	/** @type {CompressionReport} */
	var report;
	/** @type {!number} */
	var i;
	contents = [  ];
	report = new CompressionReport$();
	contents.push(Binary$dump32bitNumber$N(this._ddic));
	contents.push(Binary$dump32bitNumber$N(this._ssize));
	contents.push(Binary$dump32bitNumber$N(this._head));
	report.add$II(6, 6);
	contents.push(this._sv.dump$LCompressionReport$(report));
	if (verbose) {
		console.log("Serializing FM-index");
		console.log('    Wavelet Matrix: ' + (contents[3].length * 2 + "") + ' bytes (' + (report.rate$() + "") + '%)');
	}
	contents.push(Binary$dump32bitNumber$N(this._posdic.length));
	for (i in this._posdic) {
		contents.push(Binary$dump32bitNumber$N((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/fm-index.jsx:282:61] null access\n            contents.push(Binary.dump32bitNumber(this._posdic[i]));\n                                                             ^\n");
			}
			return v;
		}(this._posdic[i]))));
	}
	for (i in this._idic) {
		contents.push(Binary$dump32bitNumber$N((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/fm-index.jsx:286:59] null access\n            contents.push(Binary.dump32bitNumber(this._idic[i]));\n                                                           ^\n");
			}
			return v;
		}(this._idic[i]))));
	}
	if (verbose) {
		console.log('    Dictionary Cache: ' + (this._idic.length * 16 + "") + ' bytes');
	}
	return contents.join("");
};

/**
 * @param {!string} data
 * @return {!number}
 */
FMIndex.prototype.load$S = function (data) {
	return this.load$SI(data, 0);
};

/**
 * @param {!string} data
 * @param {!number} offset
 * @return {!number}
 */
FMIndex.prototype.load$SI = function (data, offset) {
	/** @type {!number} */
	var maxChar;
	/** @type {!number} */
	var c;
	/** @type {!number} */
	var size;
	/** @type {!number} */
	var i;
	this._ddic = (Binary$load32bitNumber$SI(data, offset) | 0);
	this._ssize = (Binary$load32bitNumber$SI(data, offset + 2) | 0);
	this._head = (Binary$load32bitNumber$SI(data, offset + 4) | 0);
	offset = this._sv.load$SI(data, offset + 6);
	maxChar = Math.pow(2, this._sv.bitsize$());
	for (c = 0; c < maxChar; c++) {
		this._rlt[c] = this._sv.rank_less_than$II(this._sv.size$(), c);
	}
	size = Binary$load32bitNumber$SI(data, offset);
	offset += 2;
	for (i = 0; i < size; (i++, offset += 2)) {
		this._posdic.push(Binary$load32bitNumber$SI(data, offset));
	}
	for (i = 0; i < size; (i++, offset += 2)) {
		this._idic.push(Binary$load32bitNumber$SI(data, offset));
	}
	return offset;
};

/**
 * class Tag extends Object
 * @constructor
 */
function Tag() {
}

/**
 * @constructor
 * @param {!string} name
 */
function Tag$S(name) {
	this.name = name;
	this.attributes = ({  });
	this.isSelfClosing = false;
};

Tag$S.prototype = new Tag;

/**
 * class _Common extends Object
 * @constructor
 */
function _Common() {
}

/**
 * @constructor
 */
function _Common$() {
};

_Common$.prototype = new _Common;

/**
 * class _State extends Object
 * @constructor
 */
function _State() {
}

/**
 * @constructor
 */
function _State$() {
};

_State$.prototype = new _State;

/**
 * class SAXHandler extends Object
 * @constructor
 */
function SAXHandler() {
}

/**
 * @constructor
 */
function SAXHandler$() {
	this.position = 0;
	this.column = 0;
	this.line = 0;
};

SAXHandler$.prototype = new SAXHandler;

/**
 * @param {Error} error
 */
SAXHandler.prototype.onerror$LError$ = function (error) {
};

/**
 * @param {!string} text
 */
SAXHandler.prototype.ontext$S = function (text) {
};

/**
 * @param {!string} doctype
 */
SAXHandler.prototype.ondoctype$S = function (doctype) {
};

/**
 * @param {!string} name
 * @param {!string} body
 */
SAXHandler.prototype.onprocessinginstruction$SS = function (name, body) {
};

/**
 * @param {!string} sgmlDecl
 */
SAXHandler.prototype.onsgmldeclaration$S = function (sgmlDecl) {
};

/**
 * @param {!string} tagname
 * @param {Object.<string, undefined|!string>} attributes
 */
SAXHandler.prototype.onopentag$SHS = function (tagname, attributes) {
};

/**
 * @param {!string} tagname
 */
SAXHandler.prototype.onclosetag$S = function (tagname) {
};

/**
 * @param {!string} name
 * @param {!string} value
 */
SAXHandler.prototype.onattribute$SS = function (name, value) {
};

/**
 * @param {!string} comment
 */
SAXHandler.prototype.oncomment$S = function (comment) {
};

/**
 */
SAXHandler.prototype.onopencdata$ = function () {
};

/**
 * @param {!string} cdata
 */
SAXHandler.prototype.oncdata$S = function (cdata) {
};

/**
 */
SAXHandler.prototype.onclosecdata$ = function () {
};

/**
 */
SAXHandler.prototype.onend$ = function () {
};

/**
 */
SAXHandler.prototype.onready$ = function () {
};

/**
 * @param {!string} script
 */
SAXHandler.prototype.onscript$S = function (script) {
};

/**
 * class _HTMLHandler extends SAXHandler
 * @constructor
 */
function _HTMLHandler() {
}

_HTMLHandler.prototype = new SAXHandler;
/**
 * @constructor
 * @param {Object.<string, undefined|Array.<undefined|!string>>} styles
 * @param {!boolean} escape
 */
function _HTMLHandler$HASB(styles, escape) {
	SAXHandler$.call(this);
	this.text = [  ];
	this.escape = escape;
	this.styles = styles;
};

_HTMLHandler$HASB.prototype = new _HTMLHandler;

/**
 * @param {!string} str
 * @return {!string}
 */
_HTMLHandler.escapeHTML$S = function (str) {
	return str.replace(/\n/g, "<br/>").replace(/&/g, "&amp;").replace(/"/g, "&quot;").replace(/</g, "&lt;").replace(/>/g, "&gt;");
};

var _HTMLHandler$escapeHTML$S = _HTMLHandler.escapeHTML$S;

/**
 * @param {!string} tagname
 * @param {Object.<string, undefined|!string>} attributes
 */
_HTMLHandler.prototype.onopentag$SHS = function (tagname, attributes) {
	this.text.push((function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/style.jsx:23:43] null access\n        this.text.push(this.styles[tagname][0]);\n                                           ^\n");
		}
		return v;
	}(this.styles[tagname][0])));
};

/**
 * @param {!string} tagname
 */
_HTMLHandler.prototype.onclosetag$S = function (tagname) {
	this.text.push((function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/style.jsx:28:43] null access\n        this.text.push(this.styles[tagname][1]);\n                                           ^\n");
		}
		return v;
	}(this.styles[tagname][1])));
};

/**
 * @param {!string} text
 */
_HTMLHandler.prototype.ontext$S = function (text) {
	if (this.escape) {
		this.text.push(_HTMLHandler$escapeHTML$S(text));
	} else {
		this.text.push(text);
	}
};

/**
 * @return {!string}
 */
_HTMLHandler.prototype.result$ = function () {
	return this.text.join('');
};

/**
 * class SAXParser extends Object
 * @constructor
 */
function SAXParser() {
}

/**
 * @constructor
 * @param {SAXHandler} handler
 */
function SAXParser$LSAXHandler$(handler) {
	this.q = "";
	this.c = "";
	this.bufferCheckPosition = 0;
	this.looseCase = "";
	this.tags = [  ];
	this.closed = false;
	this.closedRoot = false;
	this.sawRoot = false;
	this.tag = null;
	this.error = null;
	this.handler = null;
	this.ENTITIES = null;
	this.strict = false;
	this.tagName = "";
	this.state = 0;
	this.line = 0;
	this.column = 0;
	this.position = 0;
	this.startTagPosition = 0;
	this.attribName = "";
	this.attribValue = "";
	this.script = "";
	this.textNode = "";
	this.attribList = null;
	this.noscript = false;
	this.cdata = "";
	this.procInstBody = "";
	this.procInstName = "";
	this.doctype = "";
	this.entity = "";
	this.sgmlDecl = "";
	this.comment = "";
	this.preTags = 0;
	this._init$LSAXHandler$B(handler, false);
};

SAXParser$LSAXHandler$.prototype = new SAXParser;

/**
 * @constructor
 * @param {SAXHandler} handler
 * @param {!boolean} strict
 */
function SAXParser$LSAXHandler$B(handler, strict) {
	this.q = "";
	this.c = "";
	this.bufferCheckPosition = 0;
	this.looseCase = "";
	this.tags = [  ];
	this.closed = false;
	this.closedRoot = false;
	this.sawRoot = false;
	this.tag = null;
	this.error = null;
	this.handler = null;
	this.ENTITIES = null;
	this.strict = false;
	this.tagName = "";
	this.state = 0;
	this.line = 0;
	this.column = 0;
	this.position = 0;
	this.startTagPosition = 0;
	this.attribName = "";
	this.attribValue = "";
	this.script = "";
	this.textNode = "";
	this.attribList = null;
	this.noscript = false;
	this.cdata = "";
	this.procInstBody = "";
	this.procInstName = "";
	this.doctype = "";
	this.entity = "";
	this.sgmlDecl = "";
	this.comment = "";
	this.preTags = 0;
	this._init$LSAXHandler$B(handler, strict);
};

SAXParser$LSAXHandler$B.prototype = new SAXParser;

/**
 * @param {SAXHandler} handler
 * @param {!boolean} strict
 */
SAXParser.prototype._init$LSAXHandler$B = function (handler, strict) {
	this.handler = handler;
	this.clearBuffers$();
	this.q = "";
	this.bufferCheckPosition = (_Common.MAX_BUFFER_LENGTH | 0);
	this.looseCase = 'toLowerCase';
	this.tags = [  ];
	this.closed = this.closedRoot = this.sawRoot = false;
	this.tag = null;
	this.error = null;
	this.strict = strict;
	this.noscript = strict;
	this.state = (_State.BEGIN | 0);
	this.ENTITIES = _Entities$entity_list$();
	this.attribList = [  ];
	this.noscript = false;
	this.preTags = 0;
	this.handler.onready$();
};

/**
 * @param {!boolean} flag
 */
SAXParser.prototype.set_noscript$B = function (flag) {
	this.noscript = flag;
};

/**
 * @return {SAXParser}
 */
SAXParser.prototype.resume$ = function () {
	this.error = null;
	return this;
};

/**
 * @return {SAXParser}
 */
SAXParser.prototype.close$ = function () {
	return this.parse$S('');
};

/**
 * @param {!string} chunk
 * @return {SAXParser}
 */
SAXParser.prototype.parse$S = function (chunk) {
	/** @type {Char} */
	var _;
	/** @type {!number} */
	var i;
	/** @type {!string} */
	var c;
	/** @type {!number} */
	var starti;
	/** @type {!number} */
	var pad;
	/** @type {!number} */
	var returnState;
	_ = new Char$();
	if (this.error) {
		throw this.error;
	}
	if (this.closed) {
		return this.emiterror$S("Cannot write after close. Assign an onready handler.");
	}
	(i = 0, c = "");
	while (this.c = c = chunk.charAt(i++)) {
		this.position++;
		if (c === "\n") {
			this.handler.line++;
			this.handler.column = 0;
		} else {
			this.handler.column++;
		}
		switch (this.state) {
		case _State.BEGIN:
			if (c === "<") {
				this.state = (_State.OPEN_WAKA | 0);
				this.startTagPosition = this.position;
			} else {
				if (_.not$HBS(_.whitespace, c)) {
					this.strictFail$S("Non-whitespace before first tag.");
					this.textNode = c;
					this.state = (_State.TEXT | 0);
				}
			}
			continue;
		case _State.TEXT:
			if (this.sawRoot && ! this.closedRoot) {
				starti = i - 1;
				while (c && c !== "<" && c !== "&") {
					c = chunk.charAt(i++);
					if (c) {
						this.position++;
						if (c === "\n") {
							this.handler.line++;
							this.handler.column = 0;
						} else {
							this.handler.column++;
						}
					}
				}
				this.textNode += chunk.substring(starti, i - 1);
			}
			if (c === "<") {
				this.state = (_State.OPEN_WAKA | 0);
				this.startTagPosition = this.position;
			} else {
				if (_.not$HBS(_.whitespace, c) && (! this.sawRoot || this.closedRoot)) {
					this.strictFail$S("Text data outside of root node.");
				}
				if (c === "&") {
					this.state = (_State.TEXT_ENTITY | 0);
				} else {
					this.textNode += c;
				}
			}
			continue;
		case _State.SCRIPT:
			if (c === "<") {
				this.state = (_State.SCRIPT_ENDING | 0);
			} else {
				this.script += c;
			}
			continue;
		case _State.SCRIPT_ENDING:
			if (c === "/") {
				this.state = (_State.CLOSE_TAG | 0);
			} else {
				this.script += "<" + c;
				this.state = (_State.SCRIPT | 0);
			}
			continue;
		case _State.OPEN_WAKA:
			if (c === "!") {
				this.state = (_State.SGML_DECL | 0);
				this.sgmlDecl = "";
			} else {
				if (_.is$HBS(_.whitespace, c)) {
				} else {
					if (_.is$LRegExp$S(_.nameStart, c)) {
						this.state = (_State.OPEN_TAG | 0);
						this.tagName = c;
					} else {
						if (c === "/") {
							this.state = (_State.CLOSE_TAG | 0);
							this.tagName = "";
						} else {
							if (c === "?") {
								this.state = (_State.PROC_INST | 0);
								this.procInstName = this.procInstBody = "";
							} else {
								this.strictFail$S("Unencoded <");
								if (this.startTagPosition + 1 < this.position) {
									pad = this.position - this.startTagPosition;
									for (i = 0; i < pad; i++) {
										c = " " + c;
									}
								}
								this.textNode += "<" + c;
								this.state = (_State.TEXT | 0);
							}
						}
					}
				}
			}
			continue;
		case _State.SGML_DECL:
			if ((this.sgmlDecl + c).toUpperCase() === _.CDATA) {
				this.closetext_if_exist$();
				this.handler.onopencdata$();
				this.state = (_State.CDATA | 0);
				this.sgmlDecl = "";
				this.cdata = "";
			} else {
				if (this.sgmlDecl + c === "--") {
					this.state = (_State.COMMENT | 0);
					this.comment = "";
					this.sgmlDecl = "";
				} else {
					if ((this.sgmlDecl + c).toUpperCase() === _.DOCTYPE) {
						this.state = (_State.DOCTYPE | 0);
						if (this.doctype || this.sawRoot) {
							this.strictFail$S("Inappropriately located doctype declaration");
						}
						this.doctype = "";
						this.sgmlDecl = "";
					} else {
						if (c === ">") {
							this.closetext_if_exist$();
							this.handler.onsgmldeclaration$S(this.sgmlDecl);
							this.sgmlDecl = "";
							this.state = (_State.TEXT | 0);
						} else {
							if (_.is$HBS(_.quote, c)) {
								this.state = (_State.SGML_DECL_QUOTED | 0);
								this.sgmlDecl += c;
							} else {
								this.sgmlDecl += c;
							}
						}
					}
				}
			}
			continue;
		case _State.SGML_DECL_QUOTED:
			if (c === this.q) {
				this.state = (_State.SGML_DECL | 0);
				this.q = "";
			}
			this.sgmlDecl += c;
			continue;
		case _State.DOCTYPE:
			if (c === ">") {
				this.state = (_State.TEXT | 0);
				this.closetext_if_exist$();
				this.handler.ondoctype$S(this.doctype);
			} else {
				this.doctype += c;
				if (c === "[") {
					this.state = (_State.DOCTYPE_DTD | 0);
				} else {
					if (_.is$HBS(_.quote, c)) {
						this.state = (_State.DOCTYPE_QUOTED | 0);
						this.q = c;
					}
				}
			}
			continue;
		case _State.DOCTYPE_QUOTED:
			this.doctype += c;
			if (c === this.q) {
				this.q = "";
				this.state = (_State.DOCTYPE | 0);
			}
			continue;
		case _State.DOCTYPE_DTD:
			this.doctype += c;
			if (c === "]") {
				this.state = (_State.DOCTYPE | 0);
			} else {
				if (_.is$HBS(_.quote, c)) {
					this.state = (_State.DOCTYPE_DTD_QUOTED | 0);
					this.q = c;
				}
			}
			continue;
		case _State.DOCTYPE_DTD_QUOTED:
			this.doctype += c;
			if (c === this.q) {
				this.state = (_State.DOCTYPE_DTD | 0);
				this.q = "";
			}
			continue;
		case _State.COMMENT:
			if (c === "-") {
				this.state = (_State.COMMENT_ENDING | 0);
			} else {
				this.comment += c;
			}
			continue;
		case _State.COMMENT_ENDING:
			if (c === "-") {
				this.state = (_State.COMMENT_ENDED | 0);
				this.comment = this.textopts$S(this.comment);
				if (this.comment) {
					this.closetext_if_exist$();
					this.handler.oncomment$S(this.comment);
				}
				this.comment = "";
			} else {
				this.comment += "-" + c;
				this.state = (_State.COMMENT | 0);
			}
			continue;
		case _State.COMMENT_ENDED:
			if (c !== ">") {
				this.strictFail$S("Malformed comment");
				this.comment += "--" + c;
				this.state = (_State.COMMENT | 0);
			} else {
				this.state = (_State.TEXT | 0);
			}
			continue;
		case _State.CDATA:
			if (c === "]") {
				this.state = (_State.CDATA_ENDING | 0);
			} else {
				this.cdata += c;
			}
			continue;
		case _State.CDATA_ENDING:
			if (c === "]") {
				this.state = (_State.CDATA_ENDING_2 | 0);
			} else {
				this.cdata += "]" + c;
				this.state = (_State.CDATA | 0);
			}
			continue;
		case _State.CDATA_ENDING_2:
			if (c === ">") {
				if (this.cdata) {
					this.closetext_if_exist$();
				}
				this.handler.oncdata$S(this.cdata);
				this.handler.onclosecdata$();
				this.cdata = "";
				this.state = (_State.TEXT | 0);
			} else {
				if (c === "]") {
					this.cdata += "]";
				} else {
					this.cdata += "]]" + c;
					this.state = (_State.CDATA | 0);
				}
			}
			continue;
		case _State.PROC_INST:
			if (c === "?") {
				this.state = (_State.PROC_INST_ENDING | 0);
			} else {
				if (_.is$HBS(_.whitespace, c)) {
					this.state = (_State.PROC_INST_BODY | 0);
				} else {
					this.procInstName += c;
				}
			}
			continue;
		case _State.PROC_INST_BODY:
			if (! this.procInstBody && _.is$HBS(_.whitespace, c)) {
				continue;
			} else {
				if (c === "?") {
					this.state = (_State.PROC_INST_ENDING | 0);
				} else {
					this.procInstBody += c;
				}
			}
			continue;
		case _State.PROC_INST_ENDING:
			if (c === ">") {
				this.closetext_if_exist$();
				this.handler.onprocessinginstruction$SS(this.procInstName, this.procInstBody);
				this.procInstName = this.procInstBody = "";
				this.state = (_State.TEXT | 0);
			} else {
				this.procInstBody += "?" + c;
				this.state = (_State.PROC_INST_BODY | 0);
			}
			continue;
		case _State.OPEN_TAG:
			if (_.is$LRegExp$S(_.nameBody, c)) {
				this.tagName += c;
			} else {
				this.newTag$();
				if (c === ">") {
					this.openTag$();
				} else {
					if (c === "/") {
						this.state = (_State.OPEN_TAG_SLASH | 0);
					} else {
						if (_.not$HBS(_.whitespace, c)) {
							this.strictFail$S("Invalid character in tag name");
						}
						this.state = (_State.ATTRIB | 0);
					}
				}
			}
			continue;
		case _State.OPEN_TAG_SLASH:
			if (c === ">") {
				this.openTag$B(true);
				this.closeTag$();
			} else {
				this.strictFail$S("Forward-slash in opening tag not followed by >");
				this.state = (_State.ATTRIB | 0);
			}
			continue;
		case _State.ATTRIB:
			if (_.is$HBS(_.whitespace, c)) {
				continue;
			} else {
				if (c === ">") {
					this.openTag$();
				} else {
					if (c === "/") {
						this.state = (_State.OPEN_TAG_SLASH | 0);
					} else {
						if (_.is$LRegExp$S(_.nameStart, c)) {
							this.attribName = c;
							this.attribValue = "";
							this.state = (_State.ATTRIB_NAME | 0);
						} else {
							this.strictFail$S("Invalid attribute name");
						}
					}
				}
			}
			continue;
		case _State.ATTRIB_NAME:
			if (c === "=") {
				this.state = (_State.ATTRIB_VALUE | 0);
			} else {
				if (c === ">") {
					this.strictFail$S("Attribute without value");
					this.attribValue = this.attribName;
					this.attrib$();
					this.openTag$();
				} else {
					if (_.is$HBS(_.whitespace, c)) {
						this.state = (_State.ATTRIB_NAME_SAW_WHITE | 0);
					} else {
						if (_.is$LRegExp$S(_.nameBody, c)) {
							this.attribName += c;
						} else {
							this.strictFail$S("Invalid attribute name");
						}
					}
				}
			}
			continue;
		case _State.ATTRIB_NAME_SAW_WHITE:
			if (c === "=") {
				this.state = (_State.ATTRIB_VALUE | 0);
			} else {
				if (_.is$HBS(_.whitespace, c)) {
					continue;
				} else {
					this.strictFail$S("Attribute without value");
					this.tag.attributes[this.attribName] = "";
					this.attribValue = "";
					this.closetext_if_exist$();
					this.handler.onattribute$SS(this.attribName, "");
					this.attribName = "";
					if (c === ">") {
						this.openTag$();
					} else {
						if (_.is$LRegExp$S(_.nameStart, c)) {
							this.attribName = c;
							this.state = (_State.ATTRIB_NAME | 0);
						} else {
							this.strictFail$S("Invalid attribute name");
							this.state = (_State.ATTRIB | 0);
						}
					}
				}
			}
			continue;
		case _State.ATTRIB_VALUE:
			if (_.is$HBS(_.whitespace, c)) {
				continue;
			} else {
				if (_.is$HBS(_.quote, c)) {
					this.q = c;
					this.state = (_State.ATTRIB_VALUE_QUOTED | 0);
				} else {
					this.strictFail$S("Unquoted attribute value");
					this.state = (_State.ATTRIB_VALUE_UNQUOTED | 0);
					this.attribValue = c;
				}
			}
			continue;
		case _State.ATTRIB_VALUE_QUOTED:
			if (c !== this.q) {
				if (c === "&") {
					this.state = (_State.ATTRIB_VALUE_ENTITY_Q | 0);
				} else {
					this.attribValue += c;
				}
				continue;
			}
			this.attrib$();
			this.q = "";
			this.state = (_State.ATTRIB | 0);
			continue;
		case _State.ATTRIB_VALUE_UNQUOTED:
			if (_.not$HBS(_.attribEnd, c)) {
				if (c === "&") {
					this.state = (_State.ATTRIB_VALUE_ENTITY_U | 0);
				} else {
					this.attribValue += c;
				}
				continue;
			}
			this.attrib$();
			if (c === ">") {
				this.openTag$();
			} else {
				this.state = (_State.ATTRIB | 0);
			}
			continue;
		case _State.CLOSE_TAG:
			if (! this.tagName) {
				if (_.is$HBS(_.whitespace, c)) {
					continue;
				} else {
					if (_.not$LRegExp$S(_.nameStart, c)) {
						if (this.script) {
							this.script += "</" + c;
							this.state = (_State.SCRIPT | 0);
						} else {
							this.strictFail$S("Invalid tagname in closing tag.");
						}
					} else {
						this.tagName = c;
					}
				}
			} else {
				if (c === ">") {
					this.closeTag$();
				} else {
					if (_.is$LRegExp$S(_.nameBody, c)) {
						this.tagName += c;
					} else {
						if (this.script) {
							this.script += "</" + this.tagName;
							this.tagName = "";
							this.state = (_State.SCRIPT | 0);
						} else {
							if (_.not$HBS(_.whitespace, c)) {
								this.strictFail$S("Invalid tagname in closing tag");
							}
							this.state = (_State.CLOSE_TAG_SAW_WHITE | 0);
						}
					}
				}
			}
			continue;
		case _State.CLOSE_TAG_SAW_WHITE:
			if (_.is$HBS(_.whitespace, c)) {
				continue;
			}
			if (c === ">") {
				this.closeTag$();
			} else {
				this.strictFail$S("Invalid characters in closing tag");
			}
			continue;
		case _State.TEXT_ENTITY:
			if (c === ";") {
				this.textNode += this.parseEntity$();
				this.entity = "";
				this.state = (_State.TEXT | 0);
			} else {
				if (_.is$HBS(_.entity, c)) {
					this.entity += c;
				} else {
					this.strictFail$S("Invalid character entity");
					this.textNode += "&" + this.entity + c;
					this.entity = "";
					this.state = (_State.TEXT | 0);
				}
			}
			continue;
		case _State.ATTRIB_VALUE_ENTITY_Q:
		case _State.ATTRIB_VALUE_ENTITY_U:
			if (this.state === _State.ATTRIB_VALUE_ENTITY_Q) {
				returnState = _State.ATTRIB_VALUE_QUOTED;
			} else {
				returnState = _State.ATTRIB_VALUE_UNQUOTED;
			}
			if (c === ";") {
				this.attribValue += this.parseEntity$();
				this.entity = "";
				this.state = (returnState | 0);
			} else {
				if (_.is$HBS(_.entity, c)) {
					this.entity += c;
				} else {
					this.strictFail$S("Invalid character entity");
					this.attribValue += "&" + this.entity + c;
					this.entity = "";
					this.state = (returnState | 0);
				}
			}
			continue;
		default:
			throw new Error("Unknown state: " + (this.state + ""));
		}
	}
	this.end$();
	return this;
};

/**
 */
SAXParser.prototype.clearBuffers$ = function () {
	this.comment = '';
	this.sgmlDecl = '';
	this.textNode = '';
	this.tagName = '';
	this.doctype = '';
	this.procInstName = '';
	this.procInstBody = '';
	this.entity = '';
	this.attribName = '';
	this.attribValue = '';
	this.cdata = '';
	this.script = '';
};

/**
 */
SAXParser.prototype.closetext_if_exist$ = function () {
	if (this.textNode !== '') {
		this.closetext$();
	}
};

/**
 */
SAXParser.prototype.closetext$ = function () {
	/** @type {!string} */
	var text;
	if (this.preTags === 0) {
		text = this.textopts$S(this.textNode);
		if (text) {
			this.handler.ontext$S(text);
		}
	} else {
		if (this.textNode) {
			this.handler.ontext$S(this.textNode);
		}
	}
	this.textNode = "";
};

/**
 * @param {!string} text
 * @return {!string}
 */
SAXParser.prototype.textopts$S = function (text) {
	text = text.replace(/[\n\t]/g, ' ');
	text = text.replace(/\s\s+/g, " ");
	return text;
};

/**
 * @param {!string} er
 * @return {SAXParser}
 */
SAXParser.prototype.emiterror$S = function (er) {
	/** @type {Error} */
	var error;
	this.closetext$();
	er += "\nLine: " + (this.line + "") + "\nColumn: " + (this.column + "") + "\nChar: " + this.c;
	error = new Error(er);
	this.error = error;
	this.handler.onerror$LError$(error);
	return this;
};

/**
 */
SAXParser.prototype.end$ = function () {
	if (! this.closedRoot) {
		this.strictFail$S("Unclosed root tag");
	}
	if (this.state !== _State.TEXT) {
		this.emiterror$S("Unexpected end");
	}
	this.closetext$();
	this.c = "";
	this.closed = true;
	this.handler.onend$();
};

/**
 * @param {!string} message
 */
SAXParser.prototype.strictFail$S = function (message) {
	if (this.strict) {
		this.emiterror$S(message);
	}
};

/**
 */
SAXParser.prototype.newTag$ = function () {
	/** @type {!boolean} */
	var parent;
	/** @type {Tag} */
	var tag;
	if (! this.strict) {
		this.tagName = this.tagName.toLowerCase();
	}
	parent = !! (this.tags[this.tags.length - 1] || this);
	tag = this.tag = new Tag$S(this.tagName);
	this.attribList.length = 0;
};

/**
 */
SAXParser.prototype.attrib$ = function () {
	if (! this.strict) {
		this.attribName = this.attribName.toLowerCase();
	}
	if ($__jsx_ObjectHasOwnProperty.call(this.tag.attributes, this.attribName)) {
		this.attribName = this.attribValue = "";
		return;
	}
	this.tag.attributes[this.attribName] = this.attribValue;
	this.closetext_if_exist$();
	this.handler.onattribute$SS(this.attribName, this.attribValue);
	this.attribName = this.attribValue = "";
};

/**
 */
SAXParser.prototype.openTag$ = function () {
	this.openTag$B(false);
};

/**
 * @param {!boolean} selfClosing
 */
SAXParser.prototype.openTag$B = function (selfClosing) {
	this.tag.isSelfClosing = selfClosing;
	this.sawRoot = true;
	this.tags.push(this.tag);
	this.closetext_if_exist$();
	this.handler.onopentag$SHS(this.tag.name, this.tag.attributes);
	if (this.tag.name === 'pre') {
		this.preTags++;
	}
	if (! selfClosing) {
		if (! this.noscript && this.tagName.toLowerCase() === "script") {
			this.state = (_State.SCRIPT | 0);
		} else {
			this.state = (_State.TEXT | 0);
		}
		this.tag = null;
		this.tagName = "";
	}
	this.attribName = this.attribValue = "";
	this.attribList.length = 0;
};

/**
 */
SAXParser.prototype.closeTag$ = function () {
	/** @type {!number} */
	var t;
	/** @type {!string} */
	var tagName;
	/** @type {!string} */
	var closeTo;
	/** @type {Tag} */
	var close;
	/** @type {!number} */
	var s;
	/** @type {Tag} */
	var tag;
	/** @type {Tag} */
	var parent;
	if (! this.tagName) {
		this.strictFail$S("Weird empty close tag.");
		this.textNode += "</>";
		this.state = (_State.TEXT | 0);
		return;
	}
	if (this.script) {
		if (this.tagName !== "script") {
			this.script += "</" + this.tagName + ">";
			this.tagName = "";
			this.state = (_State.SCRIPT | 0);
			return;
		}
		this.closetext_if_exist$();
		this.handler.onscript$S(this.script);
		this.script = "";
	}
	t = this.tags.length;
	tagName = this.tagName;
	if (! this.strict) {
		tagName = tagName.toLowerCase();
	}
	closeTo = tagName;
	while (t--) {
		close = this.tags[t];
		if (close.name !== closeTo) {
			this.strictFail$S("Unexpected close tag");
		} else {
			break;
		}
	}
	if (t < 0) {
		this.strictFail$S("Unmatched closing tag: " + this.tagName);
		this.textNode += "</" + this.tagName + ">";
		this.state = (_State.TEXT | 0);
		return;
	}
	this.tagName = tagName;
	s = this.tags.length;
	while (s-- > t) {
		tag = this.tag = this.tags.pop();
		this.tagName = this.tag.name;
		this.closetext_if_exist$();
		this.handler.onclosetag$S(this.tagName);
		parent = this.tags[this.tags.length - 1];
		if (this.tagName === 'pre') {
			this.preTags--;
		}
	}
	if (t === 0) {
		this.closedRoot = true;
	}
	this.tagName = this.attribValue = this.attribName = "";
	this.attribList.length = 0;
	this.state = (_State.TEXT | 0);
};

/**
 * @return {!string}
 */
SAXParser.prototype.parseEntity$ = function () {
	/** @type {!string} */
	var entity;
	/** @type {!string} */
	var entityLC;
	/** @type {!number} */
	var num;
	/** @type {!string} */
	var numStr;
	entity = this.entity;
	entityLC = entity.toLowerCase();
	num = 0;
	numStr = "";
	if (this.ENTITIES[entity]) {
		return (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sax.jsx:977:32] null access\n            return this.ENTITIES[entity];\n                                ^\n");
			}
			return v;
		}(this.ENTITIES[entity]));
	}
	if (this.ENTITIES[entityLC]) {
		return (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sax.jsx:981:32] null access\n            return this.ENTITIES[entityLC];\n                                ^\n");
			}
			return v;
		}(this.ENTITIES[entityLC]));
	}
	entity = entityLC;
	if (entity.charAt(0) === "#") {
		if (entity.charAt(1) === "x") {
			entity = entity.slice(2);
			num = $__jsx_parseInt(entity, 16);
			numStr = num.toString(16);
		} else {
			entity = entity.slice(1);
			num = $__jsx_parseInt(entity, 10);
			numStr = num.toString(10);
		}
	}
	entity = entity.replace(/^0+/, "");
	if (numStr.toLowerCase() !== entity) {
		this.strictFail$S("Invalid character entity");
		return "&" + this.entity + ";";
	}
	return String.fromCharCode(num);
};

/**
 * class Char extends Object
 * @constructor
 */
function Char() {
}

/**
 * @constructor
 */
function Char$() {
	/** @type {!string} */
	var whitespace;
	/** @type {!string} */
	var number;
	/** @type {!string} */
	var letter;
	/** @type {!string} */
	var quote;
	/** @type {!string} */
	var entity;
	/** @type {!string} */
	var attribEnd;
	whitespace = "\r\n\t ";
	number = "0124356789";
	letter = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ";
	quote = "'\"";
	entity = number + letter + "#";
	attribEnd = whitespace + ">";
	this.CDATA = "[CDATA[";
	this.DOCTYPE = "DOCTYPE";
	this.XML_NAMESPACE = "http://www.w3.org/XML/1998/namespace";
	this.whitespace = this._charClass$S(whitespace);
	this.number = this._charClass$S(number);
	this.letter = this._charClass$S(letter);
	this.quote = this._charClass$S(quote);
	this.entity = this._charClass$S(entity);
	this.attribEnd = this._charClass$S(attribEnd);
	this.nameStart = /[:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD]/;
	this.nameBody = /[:_A-Za-z\u00C0-\u00D6\u00D8-\u00F6\u00F8-\u02FF\u0370-\u037D\u037F-\u1FFF\u200C-\u200D\u2070-\u218F\u2C00-\u2FEF\u3001-\uD7FF\uF900-\uFDCF\uFDF0-\uFFFD\u00B7\u0300-\u036F\u203F-\u2040\.\d-]/;
};

Char$.prototype = new Char;

/**
 * @param {!string} str
 * @return {Object.<string, undefined|!boolean>}
 */
Char.prototype._charClass$S = function (str) {
	/** @type {Object.<string, undefined|!boolean>} */
	var result;
	/** @type {!number} */
	var i;
	result = ({  });
	for (i = 0; i < str.length; i++) {
		result[str.slice(i, i + 1)] = true;
	}
	return result;
};

/**
 * @param {RegExp} charclass
 * @param {!string} c
 * @return {!boolean}
 */
Char.prototype.is$LRegExp$S = function (charclass, c) {
	return charclass.test(c);
};

/**
 * @param {Object.<string, undefined|!boolean>} charclass
 * @param {!string} c
 * @return {!boolean}
 */
Char.prototype.is$HBS = function (charclass, c) {
	return $__jsx_ObjectHasOwnProperty.call(charclass, c);
};

/**
 * @param {RegExp} charclass
 * @param {!string} c
 * @return {!boolean}
 */
Char.prototype.not$LRegExp$S = function (charclass, c) {
	return ! this.is$LRegExp$S(charclass, c);
};

/**
 * @param {Object.<string, undefined|!boolean>} charclass
 * @param {!string} c
 * @return {!boolean}
 */
Char.prototype.not$HBS = function (charclass, c) {
	return ! this.is$HBS(charclass, c);
};

/**
 * class _Entities extends Object
 * @constructor
 */
function _Entities() {
}

/**
 * @constructor
 */
function _Entities$() {
};

_Entities$.prototype = new _Entities;

/**
 * @return {Object.<string, undefined|!string>}
 */
_Entities.entity_list$ = function () {
	/** @type {Object.<string, undefined|!string>} */
	var result;
	/** @type {!string} */
	var key;
	/** @type {*} */
	var value;
	result = ({  });
	for (key in _Entities._entities) {
		value = _Entities._entities[key];
		if (typeof value === 'string') {
			result[key] = value + "";
		} else {
			if (typeof value === 'number') {
				result[key] = String.fromCharCode(value | 0);
			}
		}
	}
	return result;
};

var _Entities$entity_list$ = _Entities.entity_list$;

/**
 * class BitVector extends Object
 * @constructor
 */
function BitVector() {
}

/**
 * @constructor
 */
function BitVector$() {
	this._size = 0;
	this._size1 = 0;
	this._r = [  ];
	this._v = [  ];
	this.clear$();
};

BitVector$.prototype = new BitVector;

/**
 */
BitVector.prototype.build$ = function () {
	/** @type {!number} */
	var i;
	this._size1 = 0;
	for (i = 0; i < this._v.length; i++) {
		if (i % BitVector.BLOCK_RATE === 0) {
			this._r.push(this.size$B(true));
		}
		this._size1 += this._rank32$IIB((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/bit-vector.jsx:37:47] null access\n            this._size1 += this._rank32(this._v[i], BitVector.SMALL_BLOCK_SIZE, true);\n                                               ^\n");
			}
			return v;
		}(this._v[i])), BitVector.SMALL_BLOCK_SIZE, true);
	}
};

/**
 */
BitVector.prototype.clear$ = function () {
	this._v.length = 0;
	this._r.length = 0;
	this._size = 0;
	this._size1 = 0;
};

/**
 * @return {!number}
 */
BitVector.prototype.size$ = function () {
	return this._size;
};

/**
 * @param {!boolean} b
 * @return {!number}
 */
BitVector.prototype.size$B = function (b) {
	return (b ? this._size1 : this._size - this._size1);
};

/**
 * @param {!number} value
 */
BitVector.prototype.set$I = function (value) {
	this.set$IB(value, true);
};

/**
 * @param {!number} value
 * @param {!boolean} flag
 */
BitVector.prototype.set$IB = function (value, flag) {
	/** @type {!number} */
	var q;
	/** @type {!number} */
	var r;
	/** @type {!number} */
	var m;
	if (value >= this.size$()) {
		this._size = (value + 1 | 0);
	}
	q = (value / BitVector.SMALL_BLOCK_SIZE | 0);
	r = (value % BitVector.SMALL_BLOCK_SIZE | 0);
	while (q >= this._v.length) {
		this._v.push(0);
	}
	m = 0x1 << r;
	if (flag) {
		this._v[q] |= m;
	} else {
		this._v[q] &= ~ m;
	}
};

/**
 * @param {!number} value
 * @return {!boolean}
 */
BitVector.prototype.get$I = function (value) {
	/** @type {!number} */
	var q;
	/** @type {!number} */
	var r;
	/** @type {!number} */
	var m;
	if (value >= this.size$()) {
		throw new Error("BitVector.get() : range error");
	}
	q = (value / BitVector.SMALL_BLOCK_SIZE | 0);
	r = (value % BitVector.SMALL_BLOCK_SIZE | 0);
	m = 0x1 << r;
	return !! ((function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/bit-vector.jsx:96:23] null access\n        return (this._v[q] & m) as boolean;\n                       ^\n");
		}
		return v;
	}(this._v[q])) & m);
};

/**
 * @param {!number} i
 * @return {!number}
 */
BitVector.prototype.rank$I = function (i) {
	return this.rank$IB(i, true);
};

/**
 * @param {!number} i
 * @param {!boolean} b
 * @return {!number}
 */
BitVector.prototype.rank$IB = function (i, b) {
	/** @type {!number} */
	var q_large;
	/** @type {!number} */
	var q_small;
	/** @type {!number} */
	var r;
	/** @type {!number} */
	var rank;
	/** @type {!number} */
	var begin;
	/** @type {!number} */
	var j;
	if (i > this.size$()) {
		throw new Error("BitVector.rank() : range error");
	}
	if (i === 0) {
		return 0;
	}
	i--;
	q_large = (Math.floor(i / BitVector.LARGE_BLOCK_SIZE) | 0);
	q_small = (Math.floor(i / BitVector.SMALL_BLOCK_SIZE) | 0);
	r = (Math.floor(i % BitVector.SMALL_BLOCK_SIZE) | 0);
	rank = ((function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/bit-vector.jsx:118:32] null access\n        var rank : int = this._r[q_large];\n                                ^\n");
		}
		return v;
	}(this._r[q_large])) | 0);
	if (! b) {
		rank = q_large * BitVector.LARGE_BLOCK_SIZE - rank;
	}
	begin = q_large * BitVector.BLOCK_RATE;
	for (j = begin; j < q_small; j++) {
		rank += this._rank32$IIB((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/bit-vector.jsx:126:40] null access\n            rank += this._rank32(this._v[j], BitVector.SMALL_BLOCK_SIZE, b);\n                                        ^\n");
			}
			return v;
		}(this._v[j])), BitVector.SMALL_BLOCK_SIZE, b);
	}
	rank += this._rank32$IIB((function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/bit-vector.jsx:128:36] null access\n        rank += this._rank32(this._v[q_small], r + 1, b);\n                                    ^\n");
		}
		return v;
	}(this._v[q_small])), r + 1, b);
	return rank;
};

/**
 * @param {!number} i
 * @return {!number}
 */
BitVector.prototype.select$I = function (i) {
	return this.select$IB(i, true);
};

/**
 * @param {!number} i
 * @param {!boolean} b
 * @return {!number}
 */
BitVector.prototype.select$IB = function (i, b) {
	/** @type {!number} */
	var left;
	/** @type {!number} */
	var right;
	/** @type {!number} */
	var pivot;
	/** @type {undefined|!number} */
	var rank;
	/** @type {!number} */
	var j;
	if (i >= this.size$B(b)) {
		throw new Error("BitVector.select() : range error");
	}
	left = 0;
	right = this._r.length;
	while (left < right) {
		pivot = Math.floor((left + right) / 2);
		rank = this._r[pivot];
		if (! b) {
			rank = pivot * BitVector.LARGE_BLOCK_SIZE - (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/bit-vector.jsx:152:60] null access\n                rank = pivot * BitVector.LARGE_BLOCK_SIZE - rank;\n                                                            ^^^^\n");
				}
				return v;
			}(rank));
		}
		if (i < (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/bit-vector.jsx:154:20] null access\n            if (i < rank)\n                    ^^^^\n");
			}
			return v;
		}(rank))) {
			right = pivot;
		} else {
			left = pivot + 1;
		}
	}
	right--;
	if (b) {
		i -= ((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/bit-vector.jsx:167:24] null access\n            i -= this._r[right];\n                        ^\n");
			}
			return v;
		}(this._r[right])) | 0);
	} else {
		i -= (right * BitVector.LARGE_BLOCK_SIZE - (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/bit-vector.jsx:171:61] null access\n            i -= right * BitVector.LARGE_BLOCK_SIZE - this._r[right];\n                                                             ^\n");
			}
			return v;
		}(this._r[right])) | 0);
	}
	j = right * BitVector.BLOCK_RATE;
	while (1) {
		rank = this._rank32$IIB((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/bit-vector.jsx:176:43] null access\n            var rank = this._rank32(this._v[j], BitVector.SMALL_BLOCK_SIZE, b);\n                                           ^\n");
			}
			return v;
		}(this._v[j])), BitVector.SMALL_BLOCK_SIZE, b);
		if (i < (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/bit-vector.jsx:177:20] null access\n            if (i < rank)\n                    ^^^^\n");
			}
			return v;
		}(rank))) {
			break;
		}
		j++;
		i -= ((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/bit-vector.jsx:182:17] null access\n            i -= rank;\n                 ^^^^\n");
			}
			return v;
		}(rank)) | 0);
	}
	return (j * BitVector.SMALL_BLOCK_SIZE + this._select32$IIB((function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/bit-vector.jsx:184:70] null access\n        return j * BitVector.SMALL_BLOCK_SIZE + this._select32(this._v[j], i, b);\n                                                                      ^\n");
		}
		return v;
	}(this._v[j])), i, b) | 0);
};

/**
 * @param {!number} x
 * @param {!number} i
 * @param {!boolean} b
 * @return {!number}
 */
BitVector.prototype._rank32$IIB = function (x, i, b) {
	if (! b) {
		x = ~ x;
	}
	x <<= BitVector.SMALL_BLOCK_SIZE - i;
	x = ((x & 0xaaaaaaaa) >>> 1) + (x & 0x55555555);
	x = ((x & 0xcccccccc) >>> 2) + (x & 0x33333333);
	x = ((x & 0xf0f0f0f0) >>> 4) + (x & 0x0f0f0f0f);
	x = ((x & 0xff00ff00) >>> 8) + (x & 0x00ff00ff);
	x = ((x & 0xffff0000) >>> 16) + (x & 0x0000ffff);
	return x;
};

/**
 * @param {!number} x
 * @param {!number} i
 * @param {!boolean} b
 * @return {!number}
 */
BitVector.prototype._select32$IIB = function (x, i, b) {
	/** @type {!number} */
	var x1;
	/** @type {!number} */
	var x2;
	/** @type {!number} */
	var x3;
	/** @type {!number} */
	var x4;
	/** @type {!number} */
	var x5;
	/** @type {!number} */
	var pos;
	/** @type {!number} */
	var v5;
	/** @type {!number} */
	var v4;
	/** @type {!number} */
	var v3;
	/** @type {!number} */
	var v2;
	/** @type {!number} */
	var v1;
	/** @type {!number} */
	var v0;
	if (! b) {
		x = ~ x;
	}
	x1 = ((x & 0xaaaaaaaa) >>> 1) + (x & 0x55555555);
	x2 = ((x1 & 0xcccccccc) >>> 2) + (x1 & 0x33333333);
	x3 = ((x2 & 0xf0f0f0f0) >>> 4) + (x2 & 0x0f0f0f0f);
	x4 = ((x3 & 0xff00ff00) >>> 8) + (x3 & 0x00ff00ff);
	x5 = ((x4 & 0xffff0000) >>> 16) + (x4 & 0x0000ffff);
	i++;
	pos = 0;
	v5 = x5 & 0xffffffff;
	if (i > v5) {
		i -= (v5 | 0);
		pos += 32;
	}
	v4 = x4 >>> pos & 0x0000ffff;
	if (i > v4) {
		i -= (v4 | 0);
		pos += 16;
	}
	v3 = x3 >>> pos & 0x000000ff;
	if (i > v3) {
		i -= (v3 | 0);
		pos += 8;
	}
	v2 = x2 >>> pos & 0x0000000f;
	if (i > v2) {
		i -= (v2 | 0);
		pos += 4;
	}
	v1 = x1 >>> pos & 0x00000003;
	if (i > v1) {
		i -= (v1 | 0);
		pos += 2;
	}
	v0 = x >>> pos & 0x00000001;
	if (i > v0) {
		i -= (v0 | 0);
		pos += 1;
	}
	return (pos | 0);
};

/**
 * @return {!string}
 */
BitVector.prototype.dump$ = function () {
	/** @type {Array.<undefined|!string>} */
	var contents;
	contents = [  ];
	contents.push(Binary$dump32bitNumber$N(this._size));
	contents.push(Binary$dump32bitNumberList$AN(this._v));
	return contents.join('');
};

/**
 * @param {CompressionReport} report
 * @return {!string}
 */
BitVector.prototype.dump$LCompressionReport$ = function (report) {
	/** @type {Array.<undefined|!string>} */
	var contents;
	contents = [  ];
	contents.push(Binary$dump32bitNumber$N(this._size));
	report.add$II(2, 2);
	contents.push(Binary$dump32bitNumberList$ANLCompressionReport$(this._v, report));
	return contents.join('');
};

/**
 * @param {!string} data
 * @return {!number}
 */
BitVector.prototype.load$S = function (data) {
	return this.load$SI(data, 0);
};

/**
 * @param {!string} data
 * @param {!number} offset
 * @return {!number}
 */
BitVector.prototype.load$SI = function (data, offset) {
	/** @type {LoadedNumberListResult} */
	var result;
	this.clear$();
	this._size = (Binary$load32bitNumber$SI(data, offset) | 0);
	result = Binary$load32bitNumberList$SI(data, offset + 2);
	this._v = result.result;
	this.build$();
	return result.offset;
};

/**
 * class WaveletMatrix extends Object
 * @constructor
 */
function WaveletMatrix() {
}

/**
 * @constructor
 */
function WaveletMatrix$() {
	this._size = 0;
	this._range = ({  });
	this._bv = [  ];
	this._seps = [  ];
	this._bitsize = 16;
	this.clear$();
};

WaveletMatrix$.prototype = new WaveletMatrix;

/**
 * @return {!number}
 */
WaveletMatrix.prototype.bitsize$ = function () {
	return this._bitsize;
};

/**
 * @param {!number} charCode
 */
WaveletMatrix.prototype.setMaxCharCode$I = function (charCode) {
	this._bitsize = (Math.ceil(Math.log(charCode) / Math.LN2) | 0);
};

/**
 */
WaveletMatrix.prototype.clear$ = function () {
	this._bv.length = 0;
	this._seps.length = 0;
	this._size = 0;
};

/**
 * @param {!string} v
 */
WaveletMatrix.prototype.build$S = function (v) {
	/** @type {!number} */
	var size;
	/** @type {!number} */
	var bitsize;
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var depth;
	/** @type {Object.<string, undefined|!number>} */
	var range_tmp;
	/** @type {!number} */
	var code;
	/** @type {!boolean} */
	var bit;
	/** @type {!number} */
	var key;
	/** @type {Object.<string, undefined|!number>} */
	var range_rev;
	/** @type {!string} */
	var range_key;
	/** @type {!number} */
	var value;
	/** @type {!number} */
	var pos0;
	/** @type {undefined|!number} */
	var pos1;
	/** @type {!string} */
	var range_rev_key;
	/** @type {!number} */
	var begin;
	/** @type {undefined|!number} */
	var end;
	/** @type {!number} */
	var num0;
	/** @type {!number} */
	var num1;
	this.clear$();
	size = v.length;
	bitsize = this.bitsize$();
	for (i = 0; i < bitsize; i++) {
		this._bv.push(new BitVector$());
		this._seps.push(0);
	}
	this._size = (size | 0);
	for (i = 0; i < size; i++) {
		this._bv[0].set$IB(i, this._uint2bit$II(v.charCodeAt(i), 0));
	}
	this._bv[0].build$();
	this._seps[0] = this._bv[0].size$B(false);
	this._range[0 + ""] = 0;
	this._range[1 + ""] = this._seps[0];
	depth = 1;
	while (depth < bitsize) {
		range_tmp = WaveletMatrix$_shallow_copy$HI(this._range);
		for (i = 0; i < size; i++) {
			code = v.charCodeAt(i);
			bit = this._uint2bit$II(code, depth);
			key = code >>> bitsize - depth;
			this._bv[depth].set$IB((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/wavelet-matrix.jsx:76:45] null access\n                this._bv[depth].set(range_tmp[key as string], bit);\n                                             ^\n");
				}
				return v;
			}(range_tmp[key + ""])), bit);
			range_tmp[key + ""]++;
		}
		this._bv[depth].build$();
		this._seps[depth] = this._bv[depth].size$B(false);
		range_rev = ({  });
		for (range_key in this._range) {
			value = (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/wavelet-matrix.jsx:85:45] null access\n                var value : int = this._range[range_key];\n                                             ^\n");
				}
				return v;
			}(this._range[range_key]));
			if (value != range_tmp[range_key]) {
				range_rev[value + ""] = range_key | 0;
			}
		}
		this._range = ({  });
		pos0 = 0;
		pos1 = this._seps[depth];
		for (range_rev_key in range_rev) {
			begin = range_rev_key | 0;
			value = (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/wavelet-matrix.jsx:97:37] null access\n                var value = range_rev[range_rev_key];\n                                     ^\n");
				}
				return v;
			}(range_rev[range_rev_key]));
			end = range_tmp[value + ""];
			num0 = this._bv[depth].rank$IB((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/wavelet-matrix.jsx:99:49] null access\n                var num0  = this._bv[depth].rank(end  , false) -\n                                                 ^^^\n");
				}
				return v;
			}(end)), false) - this._bv[depth].rank$IB(begin, false);
			num1 = (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/wavelet-matrix.jsx:101:28] null access\n                var num1  = end - begin - num0;\n                            ^^^\n");
				}
				return v;
			}(end)) - begin - num0;
			if (num0 > 0) {
				this._range[(value << 1) + ""] = (pos0 | 0);
				pos0 += num0;
			}
			if (num1 > 0) {
				this._range[(value << 1) + 1 + ""] = pos1;
				pos1 += (num1 | 0);
			}
		}
		depth++;
	}
};

/**
 * @return {!number}
 */
WaveletMatrix.prototype.size$ = function () {
	return this._size;
};

/**
 * @param {!number} c
 * @return {!number}
 */
WaveletMatrix.prototype.size$I = function (c) {
	return this.rank$II(this.size$(), c);
};

/**
 * @param {!number} i
 * @return {!number}
 */
WaveletMatrix.prototype.get$I = function (i) {
	/** @type {!number} */
	var value;
	/** @type {!number} */
	var depth;
	/** @type {!boolean} */
	var bit;
	if (i >= this.size$()) {
		throw new Error("WaveletMatrix.get() : range error");
	}
	value = 0;
	depth = 0;
	while (depth < this.bitsize$()) {
		bit = this._bv[depth].get$I(i);
		i = this._bv[depth].rank$IB(i, bit);
		value <<= 1;
		if (bit) {
			i += (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/wavelet-matrix.jsx:142:31] null access\n                i += this._seps[depth];\n                               ^\n");
				}
				return v;
			}(this._seps[depth]));
			value += 1;
		}
		depth++;
	}
	return (value | 0);
};

/**
 * @param {!number} i
 * @param {!number} c
 * @return {!number}
 */
WaveletMatrix.prototype.rank$II = function (i, c) {
	/** @type {undefined|!number} */
	var begin;
	/** @type {!number} */
	var end;
	/** @type {!number} */
	var depth;
	/** @type {!boolean} */
	var bit;
	if (i > this.size$()) {
		throw new Error("WaveletMatrix.rank(): range error");
	}
	if (i === 0) {
		return 0;
	}
	begin = this._range[c + ""];
	if (begin == null) {
		return 0;
	}
	end = i;
	depth = 0;
	while (depth < this.bitsize$()) {
		bit = this._uint2bit$II(c, depth);
		end = this._bv[depth].rank$IB(end, bit);
		if (bit) {
			end += (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/wavelet-matrix.jsx:174:33] null access\n                end += this._seps[depth];\n                                 ^\n");
				}
				return v;
			}(this._seps[depth]));
		}
		depth++;
	}
	return (end - (function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/wavelet-matrix.jsx:178:21] null access\n        return end - begin;\n                     ^^^^^\n");
		}
		return v;
	}(begin)) | 0);
};

/**
 * @param {!number} i
 * @param {!number} c
 * @return {!number}
 */
WaveletMatrix.prototype.rank_less_than$II = function (i, c) {
	/** @type {!number} */
	var begin;
	/** @type {!number} */
	var end;
	/** @type {!number} */
	var depth;
	/** @type {!number} */
	var rlt;
	/** @type {!number} */
	var rank0_begin;
	/** @type {!number} */
	var rank0_end;
	if (i > this.size$()) {
		throw new Error("WaveletMatrix.rank_less_than(): range error");
	}
	if (i === 0) {
		return 0;
	}
	begin = 0;
	end = i;
	depth = 0;
	rlt = 0;
	while (depth < this.bitsize$()) {
		rank0_begin = this._bv[depth].rank$IB(begin, false);
		rank0_end = this._bv[depth].rank$IB(end, false);
		if (this._uint2bit$II(c, depth)) {
			rlt += rank0_end - rank0_begin;
			begin += (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/wavelet-matrix.jsx:203:36] null access\n                begin += (this._seps[depth] - rank0_begin);\n                                    ^\n");
				}
				return v;
			}(this._seps[depth])) - rank0_begin;
			end += (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/wavelet-matrix.jsx:204:36] null access\n                end   += (this._seps[depth] - rank0_end);\n                                    ^\n");
				}
				return v;
			}(this._seps[depth])) - rank0_end;
		} else {
			begin = rank0_begin;
			end = rank0_end;
		}
		depth++;
	}
	return (rlt | 0);
};

/**
 * @return {!string}
 */
WaveletMatrix.prototype.dump$ = function () {
	/** @type {Array.<undefined|!string>} */
	var contents;
	/** @type {!number} */
	var i;
	/** @type {Array.<undefined|!string>} */
	var range_contents;
	/** @type {!number} */
	var counter;
	/** @type {!string} */
	var key;
	contents = [ Binary$dump16bitNumber$I(this._bitsize), Binary$dump32bitNumber$N(this._size) ];
	for (i = 0; i < this.bitsize$(); i++) {
		contents.push(this._bv[i].dump$());
	}
	for (i = 0; i < this.bitsize$(); i++) {
		contents.push(Binary$dump32bitNumber$N((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/wavelet-matrix.jsx:228:59] null access\n            contents.push(Binary.dump32bitNumber(this._seps[i]));\n                                                           ^\n");
			}
			return v;
		}(this._seps[i]))));
	}
	range_contents = [  ];
	counter = 0;
	for (key in this._range) {
		range_contents.push(Binary$dump32bitNumber$N(key | 0));
		range_contents.push(Binary$dump32bitNumber$N((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/wavelet-matrix.jsx:235:66] null access\n            range_contents.push(Binary.dump32bitNumber(this._range[key]));\n                                                                  ^\n");
			}
			return v;
		}(this._range[key]))));
		counter++;
	}
	contents.push(Binary$dump32bitNumber$N(counter));
	return contents.join('') + range_contents.join('');
};

/**
 * @param {CompressionReport} report
 * @return {!string}
 */
WaveletMatrix.prototype.dump$LCompressionReport$ = function (report) {
	/** @type {Array.<undefined|!string>} */
	var contents;
	/** @type {!number} */
	var i;
	/** @type {Array.<undefined|!string>} */
	var range_contents;
	/** @type {!number} */
	var counter;
	/** @type {!string} */
	var key;
	contents = [ Binary$dump16bitNumber$I(this._bitsize), Binary$dump32bitNumber$N(this._size) ];
	report.add$II(3, 3);
	for (i = 0; i < this.bitsize$(); i++) {
		contents.push(this._bv[i].dump$LCompressionReport$(report));
	}
	for (i = 0; i < this.bitsize$(); i++) {
		contents.push(Binary$dump32bitNumber$N((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/wavelet-matrix.jsx:255:59] null access\n            contents.push(Binary.dump32bitNumber(this._seps[i]));\n                                                           ^\n");
			}
			return v;
		}(this._seps[i]))));
		report.add$II(2, 2);
	}
	range_contents = [  ];
	counter = 0;
	for (key in this._range) {
		range_contents.push(Binary$dump32bitNumber$N(key | 0));
		range_contents.push(Binary$dump32bitNumber$N((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/wavelet-matrix.jsx:263:66] null access\n            range_contents.push(Binary.dump32bitNumber(this._range[key]));\n                                                                  ^\n");
			}
			return v;
		}(this._range[key]))));
		report.add$II(4, 4);
		counter++;
	}
	report.add$II(2, 2);
	contents.push(Binary$dump32bitNumber$N(counter));
	return contents.join('') + range_contents.join('');
};

/**
 * @param {!string} data
 * @return {!number}
 */
WaveletMatrix.prototype.load$S = function (data) {
	return this.load$SI(data, 0);
};

/**
 * @param {!string} data
 * @param {!number} offset
 * @return {!number}
 */
WaveletMatrix.prototype.load$SI = function (data, offset) {
	/** @type {!number} */
	var i;
	/** @type {BitVector} */
	var bit_vector;
	/** @type {!number} */
	var sep;
	/** @type {!number} */
	var range_size;
	/** @type {!number} */
	var key;
	/** @type {!number} */
	var value;
	this.clear$();
	this._bitsize = Binary$load16bitNumber$SI(data, offset++);
	this._size = (Binary$load32bitNumber$SI(data, offset) | 0);
	offset += 2;
	for (i = 0; i < this.bitsize$(); i++) {
		bit_vector = new BitVector$();
		offset = bit_vector.load$SI(data, offset);
		this._bv.push(bit_vector);
	}
	sep = 0;
	for (i = 0; i < this.bitsize$(); (i++, offset += 2)) {
		this._seps.push(Binary$load32bitNumber$SI(data, offset));
	}
	range_size = Binary$load32bitNumber$SI(data, offset);
	offset += 2;
	for (i = 0; i < range_size; (i++, offset += 4)) {
		key = Binary$load32bitNumber$SI(data, offset);
		value = Binary$load32bitNumber$SI(data, offset + 2);
		this._range[key + ""] = (value | 0);
	}
	return offset;
};

/**
 * @param {Object.<string, undefined|!number>} input
 * @return {Object.<string, undefined|!number>}
 */
WaveletMatrix._shallow_copy$HI = function (input) {
	/** @type {Object.<string, undefined|!number>} */
	var result;
	/** @type {!string} */
	var key;
	result = ({  });
	for (key in input) {
		result[key] = input[key];
	}
	return result;
};

var WaveletMatrix$_shallow_copy$HI = WaveletMatrix._shallow_copy$HI;

/**
 * @param {!number} c
 * @param {!number} i
 * @return {!boolean}
 */
WaveletMatrix.prototype._uint2bit$II = function (c, i) {
	return (c >>> this._bitsize - 1 - i & 0x1) === 0x1;
};

/**
 * class BurrowsWheelerTransform extends Object
 * @constructor
 */
function BurrowsWheelerTransform() {
}

/**
 * @constructor
 */
function BurrowsWheelerTransform$() {
	this._str = "";
	this._size = 0;
	this._head = 0;
	this._suffixarray = [  ];
};

BurrowsWheelerTransform$.prototype = new BurrowsWheelerTransform;

/**
 * @return {!number}
 */
BurrowsWheelerTransform.prototype.size$ = function () {
	return this._size;
};

/**
 * @return {!number}
 */
BurrowsWheelerTransform.prototype.head$ = function () {
	return this._head;
};

/**
 */
BurrowsWheelerTransform.prototype.clear$ = function () {
	this._str = "";
	this._size = 0;
	this._head = 0;
	this._suffixarray.length = 0;
};

/**
 * @param {!string} str
 */
BurrowsWheelerTransform.prototype.build$S = function (str) {
	this._str = str;
	this._size = this._str.length;
	this._suffixarray = SAIS$make$S(str);
	this._head = (this._suffixarray.indexOf(0) | 0);
};

/**
 * @param {!number} i
 * @return {!string}
 */
BurrowsWheelerTransform.prototype.get$I = function (i) {
	/** @type {!number} */
	var size;
	/** @type {!number} */
	var index;
	size = this.size$();
	if (i >= size) {
		throw new Error("BurrowsWheelerTransform.get() : range error");
	}
	index = ((function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/burrows-wheeler-transform.jsx:52:38] null access\n        var index = (this._suffixarray[i] + size - 1) % size;\n                                      ^\n");
		}
		return v;
	}(this._suffixarray[i])) + size - 1) % size;
	return this._str.charAt(index);
};

/**
 * @return {!string}
 */
BurrowsWheelerTransform.prototype.get$ = function () {
	/** @type {Array.<undefined|!string>} */
	var str;
	/** @type {!number} */
	var size;
	/** @type {!number} */
	var i;
	str = [  ];
	size = this.size$();
	for (i = 0; i < size; i++) {
		str.push(this.get$I(i));
	}
	return str.join("");
};

/**
 * @param {!string} replace
 * @return {!string}
 */
BurrowsWheelerTransform.prototype.get$S = function (replace) {
	/** @type {!string} */
	var result;
	result = this.get$();
	return result.replace(BurrowsWheelerTransform.END_MARKER, replace);
};

/**
 * class OArray extends Object
 * @constructor
 */
function OArray() {
}

/**
 * @constructor
 * @param {Array.<undefined|!number>} array
 */
function OArray$AI(array) {
	this.array = array;
	this.offset = 0;
};

OArray$AI.prototype = new OArray;

/**
 * @constructor
 * @param {Array.<undefined|!number>} array
 * @param {!number} offset
 */
function OArray$AII(array, offset) {
	this.array = array;
	this.offset = offset;
};

OArray$AII.prototype = new OArray;

/**
 * @param {!number} index
 * @return {!number}
 */
OArray.prototype.get$I = function (index) {
	return (function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/sais.jsx:27:25] null access\n        return this.array[index + this.offset];\n                         ^\n");
		}
		return v;
	}(this.array[index + this.offset]));
};

/**
 * @param {!number} index
 * @param {!number} value
 */
OArray.prototype.set$II = function (index, value) {
	this.array[index + this.offset] = value;
};

/**
 * @param {!number} index
 * @return {!boolean}
 */
OArray.prototype.isS$I = function (index) {
	return (function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/sais.jsx:37:25] null access\n        return this.array[index + this.offset] < this.array[index + this.offset + 1];\n                         ^\n");
		}
		return v;
	}(this.array[index + this.offset])) < (function (v) {
		if (! (v != null)) {
			debugger;
			throw new Error("[src/sais.jsx:37:59] null access\n        return this.array[index + this.offset] < this.array[index + this.offset + 1];\n                                                           ^\n");
		}
		return v;
	}(this.array[index + this.offset + 1]));
};

/**
 * @param {!number} index1
 * @param {!number} index2
 * @return {!boolean}
 */
OArray.prototype.compare$II = function (index1, index2) {
	return this.array[index1 + this.offset] == this.array[index2 + this.offset];
};

/**
 * class SAIS extends Object
 * @constructor
 */
function SAIS() {
}

/**
 * @constructor
 */
function SAIS$() {
};

SAIS$.prototype = new SAIS;

/**
 * @param {BitVector} t
 * @param {!number} i
 * @return {!boolean}
 */
SAIS._isLMS$LBitVector$I = function (t, i) {
	return i > 0 && t.get$I(i) && ! t.get$I(i - 1);
};

var SAIS$_isLMS$LBitVector$I = SAIS._isLMS$LBitVector$I;

/**
 * @param {OArray} s
 * @param {Array.<undefined|!number>} bkt
 * @param {!number} n
 * @param {!number} K
 * @param {!boolean} end
 */
SAIS._getBuckets$LOArray$AIIIB = function (s, bkt, n, K, end) {
	/** @type {!number} */
	var sum;
	/** @type {!number} */
	var i;
	sum = 0;
	for (i = 0; i <= K; i++) {
		bkt[i] = 0;
	}
	for (i = 0; i < n; i++) {
		bkt[s.get$I(i)]++;
	}
	for (i = 0; i <= K; i++) {
		sum += (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:68:22] null access\n            sum += bkt[i];\n                      ^\n");
			}
			return v;
		}(bkt[i]));
		bkt[i] = ((end ? sum : sum - (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:69:42] null access\n            bkt[i] = end ? sum : sum - bkt[i];\n                                          ^\n");
			}
			return v;
		}(bkt[i]))) | 0);
	}
};

var SAIS$_getBuckets$LOArray$AIIIB = SAIS._getBuckets$LOArray$AIIIB;

/**
 * @param {BitVector} t
 * @param {Array.<undefined|!number>} SA
 * @param {OArray} s
 * @param {Array.<undefined|!number>} bkt
 * @param {!number} n
 * @param {!number} K
 * @param {!boolean} end
 */
SAIS._induceSAl$LBitVector$AILOArray$AIIIB = function (t, SA, s, bkt, n, K, end) {
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var j;
	SAIS$_getBuckets$LOArray$AIIIB(s, bkt, n, K, end);
	for (i = 0; i < n; i++) {
		j = (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:79:22] null access\n            var j = SA[i] - 1;\n                      ^\n");
			}
			return v;
		}(SA[i])) - 1;
		if (j >= 0 && ! t.get$I(j)) {
			SA[bkt[s.get$I(j)]++] = (j | 0);
		}
	}
};

var SAIS$_induceSAl$LBitVector$AILOArray$AIIIB = SAIS._induceSAl$LBitVector$AILOArray$AIIIB;

/**
 * @param {BitVector} t
 * @param {Array.<undefined|!number>} SA
 * @param {OArray} s
 * @param {Array.<undefined|!number>} bkt
 * @param {!number} n
 * @param {!number} K
 * @param {!boolean} end
 */
SAIS._induceSAs$LBitVector$AILOArray$AIIIB = function (t, SA, s, bkt, n, K, end) {
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var j;
	SAIS$_getBuckets$LOArray$AIIIB(s, bkt, n, K, end);
	for (i = n - 1; i >= 0; i--) {
		j = (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:93:22] null access\n            var j = SA[i] - 1;\n                      ^\n");
			}
			return v;
		}(SA[i])) - 1;
		if (j >= 0 && t.get$I(j)) {
			SA[-- bkt[s.get$I(j)]] = (j | 0);
		}
	}
};

var SAIS$_induceSAs$LBitVector$AILOArray$AIIIB = SAIS._induceSAs$LBitVector$AILOArray$AIIIB;

/**
 * @param {!string} source
 * @return {Array.<undefined|!number>}
 */
SAIS.make$S = function (source) {
	/** @type {Array.<undefined|!number>} */
	var charCodes;
	/** @type {!number} */
	var maxCode;
	/** @type {!number} */
	var i;
	/** @type {!number} */
	var code;
	/** @type {Array.<undefined|!number>} */
	var SA;
	/** @type {OArray} */
	var s;
	charCodes = [  ];
	charCodes.length = source.length;
	maxCode = 0;
	for (i = 0; i < source.length; i++) {
		code = source.charCodeAt(i);
		charCodes[i] = (code | 0);
		maxCode = (code > maxCode ? code : maxCode);
	}
	SA = [  ];
	SA.length = source.length;
	s = new OArray$AI(charCodes);
	SAIS$_make$LOArray$AIII(s, SA, source.length, maxCode);
	return SA;
};

var SAIS$make$S = SAIS.make$S;

/**
 * @param {OArray} s
 * @param {Array.<undefined|!number>} SA
 * @param {!number} n
 * @param {!number} K
 */
SAIS._make$LOArray$AIII = function (s, SA, n, K) {
	/** @type {BitVector} */
	var t;
	/** @type {!number} */
	var i;
	/** @type {Array.<undefined|!number>} */
	var bkt;
	/** @type {!number} */
	var n1;
	/** @type {!number} */
	var name;
	/** @type {!number} */
	var prev;
	/** @type {undefined|!number} */
	var pos;
	/** @type {!boolean} */
	var diff;
	/** @type {!number} */
	var d;
	/** @type {!number} */
	var j;
	/** @type {Array.<undefined|!number>} */
	var SA1;
	/** @type {OArray} */
	var s1;
	t = new BitVector$();
	t.set$IB(n - 2, false);
	t.set$IB(n - 1, true);
	for (i = n - 3; i >= 0; i--) {
		t.set$IB(i, s.isS$I(i) || s.compare$II(i, i + 1) && t.get$I(i + 1));
	}
	bkt = [  ];
	bkt.length = K + 1;
	SAIS$_getBuckets$LOArray$AIIIB(s, bkt, n, K, true);
	for (i = 0; i < n; i++) {
		SA[i] = (- 1 | 0);
	}
	for (i = 1; i < n; i++) {
		if (SAIS$_isLMS$LBitVector$I(t, i)) {
			SA[-- bkt[s.get$I(i)]] = (i | 0);
		}
	}
	SAIS$_induceSAl$LBitVector$AILOArray$AIIIB(t, SA, s, bkt, n, K, false);
	SAIS$_induceSAs$LBitVector$AILOArray$AIIIB(t, SA, s, bkt, n, K, true);
	n1 = 0;
	for (i = 0; i < n; i++) {
		if (SAIS$_isLMS$LBitVector$I(t, (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:157:33] null access\n            if (SAIS._isLMS(t, SA[i]))\n                                 ^\n");
			}
			return v;
		}(SA[i])))) {
			SA[n1++] = SA[i];
		}
	}
	for (i = n1; i < n; i++) {
		SA[i] = (- 1 | 0);
	}
	name = 0;
	prev = - 1;
	for (i = 0; i < n1; i++) {
		pos = SA[i];
		diff = false;
		for (d = 0; d < n; d++) {
			if (prev === - 1 || ! s.compare$II((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/sais.jsx:176:45] null access\n                if (prev == -1 || !s.compare(pos + d, prev + d) || t.get(pos + d) != t.get(prev + d))\n                                             ^^^\n");
				}
				return v;
			}(pos)) + d, prev + d) || t.get$I((function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/sais.jsx:176:73] null access\n                if (prev == -1 || !s.compare(pos + d, prev + d) || t.get(pos + d) != t.get(prev + d))\n                                                                         ^^^\n");
				}
				return v;
			}(pos)) + d) !== t.get$I(prev + d)) {
				diff = true;
				break;
			} else {
				if (d > 0 && (SAIS$_isLMS$LBitVector$I(t, (function (v) {
					if (! (v != null)) {
						debugger;
						throw new Error("[src/sais.jsx:181:50] null access\n                else if (d > 0 && (SAIS._isLMS(t, pos+d) || SAIS._isLMS(t, prev + d)))\n                                                  ^^^\n");
					}
					return v;
				}(pos)) + d) || SAIS$_isLMS$LBitVector$I(t, prev + d))) {
					break;
				}
			}
		}
		if (diff) {
			name++;
			prev = (function (v) {
				if (! (v != null)) {
					debugger;
					throw new Error("[src/sais.jsx:189:23] null access\n                prev = pos;\n                       ^^^\n");
				}
				return v;
			}(pos));
		}
		pos = (((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:191:19] null access\n            pos = (pos % 2 == 0) ? pos / 2 : (pos - 1) / 2;\n                   ^^^\n");
			}
			return v;
		}(pos)) % 2 === 0 ? (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:191:35] null access\n            pos = (pos % 2 == 0) ? pos / 2 : (pos - 1) / 2;\n                                   ^^^\n");
			}
			return v;
		}(pos)) / 2 : ((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:191:46] null access\n            pos = (pos % 2 == 0) ? pos / 2 : (pos - 1) / 2;\n                                              ^^^\n");
			}
			return v;
		}(pos)) - 1) / 2) | 0);
		SA[n1 + (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:192:20] null access\n            SA[n1 + pos] = name - 1;\n                    ^^^\n");
			}
			return v;
		}(pos))] = (name - 1 | 0);
	}
	for ((i = n - 1, j = n - 1); i >= n1; i--) {
		if ((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:196:18] null access\n            if (SA[i] >= 0)\n                  ^\n");
			}
			return v;
		}(SA[i])) >= 0) {
			SA[j--] = SA[i];
		}
	}
	SA1 = SA;
	s1 = new OArray$AII(SA, n - n1);
	if (name < n1) {
		SAIS$_make$LOArray$AIII(s1, SA1, n1, name - 1);
	} else {
		for (i = 0; i < n1; i++) {
			SA1[s1.get$I(i)] = (i | 0);
		}
	}
	bkt = [  ];
	bkt.length = K + 1;
	SAIS$_getBuckets$LOArray$AIIIB(s, bkt, n, K, true);
	for ((i = 1, j = 0); i < n; i++) {
		if (SAIS$_isLMS$LBitVector$I(t, i)) {
			s1.set$II(j++, i);
		}
	}
	for (i = 0; i < n1; i++) {
		SA1[i] = s1.get$I((function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:235:31] null access\n            SA1[i] = s1.get(SA1[i]); // get index in s\n                               ^\n");
			}
			return v;
		}(SA1[i])));
	}
	for (i = n1; i < n; i++) {
		SA[i] = (- 1 | 0);
	}
	for (i = n1 - 1; i >= 0; i--) {
		j = (function (v) {
			if (! (v != null)) {
				debugger;
				throw new Error("[src/sais.jsx:243:18] null access\n            j = SA[i];\n                  ^\n");
			}
			return v;
		}(SA[i]));
		SA[i] = (- 1 | 0);
		SA[-- bkt[s.get$I(j)]] = (j | 0);
	}
	SAIS$_induceSAl$LBitVector$AILOArray$AIIIB(t, SA, s, bkt, n, K, false);
	SAIS$_induceSAs$LBitVector$AILOArray$AIIIB(t, SA, s, bkt, n, K, true);
};

var SAIS$_make$LOArray$AIII = SAIS._make$LOArray$AIII;

OktaviaSearch._stemmer = null;
OktaviaSearch._instance = null;
$__jsx_lazy_init(Oktavia, "eof", function () {
	return String.fromCharCode(0);
});
$__jsx_lazy_init(Oktavia, "eob", function () {
	return String.fromCharCode(1);
});
$__jsx_lazy_init(Oktavia, "unknown", function () {
	return String.fromCharCode(3);
});
Binary._base64EncodeChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
$__jsx_lazy_init(Binary, "_base64DecodeChars", function () {
	return [ - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, - 1, 62, - 1, - 1, - 1, 63, 52, 53, 54, 55, 56, 57, 58, 59, 60, 61, - 1, - 1, - 1, - 1, - 1, - 1, - 1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, - 1, - 1, - 1, - 1, - 1, - 1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, - 1, - 1, - 1, - 1, - 1 ];
});
$__jsx_lazy_init(Style, "console", function () {
	return ({ 'title': [ '\x1B[32m\x1b[4m', '\x1B[39m\x1b[0m' ], 'url': [ '\x1B[34m', '\x1B[39m' ], 'hit': [ '\x1B[4m', '\x1B[0m' ], 'del': [ '\x1B[9m', '\x1B[0m' ], 'summary': [ '\x1B[90m', '\x1B[39m' ] });
});
$__jsx_lazy_init(Style, "html", function () {
	return ({ 'title': [ '<span class="title">', '</span>' ], 'url': [ '<span class="url">', '</span>' ], 'hit': [ '<span class="hit">', '</span>' ], 'del': [ '<del>', '</del>' ], 'summary': [ '<span class="reuslt">', '</span>' ] });
});
$__jsx_lazy_init(Style, "ignore", function () {
	return ({ 'tilte': [ '', '' ], 'url': [ '', '' ], 'hit': [ '', '' ], 'del': [ '', '' ], 'summary': [ '', '' ] });
});
EnglishStemmer.serialVersionUID = 1;
$__jsx_lazy_init(EnglishStemmer, "methodObject", function () {
	return new EnglishStemmer$();
});
$__jsx_lazy_init(EnglishStemmer, "a_0", function () {
	return [ new Among$SII("arsen", - 1, - 1), new Among$SII("commun", - 1, - 1), new Among$SII("gener", - 1, - 1) ];
});
$__jsx_lazy_init(EnglishStemmer, "a_1", function () {
	return [ new Among$SII("'", - 1, 1), new Among$SII("'s'", 0, 1), new Among$SII("'s", - 1, 1) ];
});
$__jsx_lazy_init(EnglishStemmer, "a_2", function () {
	return [ new Among$SII("ied", - 1, 2), new Among$SII("s", - 1, 3), new Among$SII("ies", 1, 2), new Among$SII("sses", 1, 1), new Among$SII("ss", 1, - 1), new Among$SII("us", 1, - 1) ];
});
$__jsx_lazy_init(EnglishStemmer, "a_3", function () {
	return [ new Among$SII("", - 1, 3), new Among$SII("bb", 0, 2), new Among$SII("dd", 0, 2), new Among$SII("ff", 0, 2), new Among$SII("gg", 0, 2), new Among$SII("bl", 0, 1), new Among$SII("mm", 0, 2), new Among$SII("nn", 0, 2), new Among$SII("pp", 0, 2), new Among$SII("rr", 0, 2), new Among$SII("at", 0, 1), new Among$SII("tt", 0, 2), new Among$SII("iz", 0, 1) ];
});
$__jsx_lazy_init(EnglishStemmer, "a_4", function () {
	return [ new Among$SII("ed", - 1, 2), new Among$SII("eed", 0, 1), new Among$SII("ing", - 1, 2), new Among$SII("edly", - 1, 2), new Among$SII("eedly", 3, 1), new Among$SII("ingly", - 1, 2) ];
});
$__jsx_lazy_init(EnglishStemmer, "a_5", function () {
	return [ new Among$SII("anci", - 1, 3), new Among$SII("enci", - 1, 2), new Among$SII("ogi", - 1, 13), new Among$SII("li", - 1, 16), new Among$SII("bli", 3, 12), new Among$SII("abli", 4, 4), new Among$SII("alli", 3, 8), new Among$SII("fulli", 3, 14), new Among$SII("lessli", 3, 15), new Among$SII("ousli", 3, 10), new Among$SII("entli", 3, 5), new Among$SII("aliti", - 1, 8), new Among$SII("biliti", - 1, 12), new Among$SII("iviti", - 1, 11), new Among$SII("tional", - 1, 1), new Among$SII("ational", 14, 7), new Among$SII("alism", - 1, 8), new Among$SII("ation", - 1, 7), new Among$SII("ization", 17, 6), new Among$SII("izer", - 1, 6), new Among$SII("ator", - 1, 7), new Among$SII("iveness", - 1, 11), new Among$SII("fulness", - 1, 9), new Among$SII("ousness", - 1, 10) ];
});
$__jsx_lazy_init(EnglishStemmer, "a_6", function () {
	return [ new Among$SII("icate", - 1, 4), new Among$SII("ative", - 1, 6), new Among$SII("alize", - 1, 3), new Among$SII("iciti", - 1, 4), new Among$SII("ical", - 1, 4), new Among$SII("tional", - 1, 1), new Among$SII("ational", 5, 2), new Among$SII("ful", - 1, 5), new Among$SII("ness", - 1, 5) ];
});
$__jsx_lazy_init(EnglishStemmer, "a_7", function () {
	return [ new Among$SII("ic", - 1, 1), new Among$SII("ance", - 1, 1), new Among$SII("ence", - 1, 1), new Among$SII("able", - 1, 1), new Among$SII("ible", - 1, 1), new Among$SII("ate", - 1, 1), new Among$SII("ive", - 1, 1), new Among$SII("ize", - 1, 1), new Among$SII("iti", - 1, 1), new Among$SII("al", - 1, 1), new Among$SII("ism", - 1, 1), new Among$SII("ion", - 1, 2), new Among$SII("er", - 1, 1), new Among$SII("ous", - 1, 1), new Among$SII("ant", - 1, 1), new Among$SII("ent", - 1, 1), new Among$SII("ment", 15, 1), new Among$SII("ement", 16, 1) ];
});
$__jsx_lazy_init(EnglishStemmer, "a_8", function () {
	return [ new Among$SII("e", - 1, 1), new Among$SII("l", - 1, 2) ];
});
$__jsx_lazy_init(EnglishStemmer, "a_9", function () {
	return [ new Among$SII("succeed", - 1, - 1), new Among$SII("proceed", - 1, - 1), new Among$SII("exceed", - 1, - 1), new Among$SII("canning", - 1, - 1), new Among$SII("inning", - 1, - 1), new Among$SII("earring", - 1, - 1), new Among$SII("herring", - 1, - 1), new Among$SII("outing", - 1, - 1) ];
});
$__jsx_lazy_init(EnglishStemmer, "a_10", function () {
	return [ new Among$SII("andes", - 1, - 1), new Among$SII("atlas", - 1, - 1), new Among$SII("bias", - 1, - 1), new Among$SII("cosmos", - 1, - 1), new Among$SII("dying", - 1, 3), new Among$SII("early", - 1, 9), new Among$SII("gently", - 1, 7), new Among$SII("howe", - 1, - 1), new Among$SII("idly", - 1, 6), new Among$SII("lying", - 1, 4), new Among$SII("news", - 1, - 1), new Among$SII("only", - 1, 10), new Among$SII("singly", - 1, 11), new Among$SII("skies", - 1, 2), new Among$SII("skis", - 1, 1), new Among$SII("sky", - 1, - 1), new Among$SII("tying", - 1, 5), new Among$SII("ugly", - 1, 8) ];
});
$__jsx_lazy_init(EnglishStemmer, "g_v", function () {
	return [ 17, 65, 16, 1 ];
});
$__jsx_lazy_init(EnglishStemmer, "g_v_WXY", function () {
	return [ 1, 17, 65, 208, 1 ];
});
$__jsx_lazy_init(EnglishStemmer, "g_valid_LI", function () {
	return [ 55, 141, 2 ];
});
$__jsx_lazy_init(_Common, "buffers", function () {
	return [ "comment", "sgmlDecl", "textNode", "tagName", "doctype", "procInstName", "procInstBody", "entity", "attribName", "attribValue", "cdata", "script" ];
});
$__jsx_lazy_init(_Common, "EVENTS", function () {
	return [ "text", "processinginstruction", "sgmldeclaration", "doctype", "comment", "attribute", "opentag", "closetag", "opencdata", "cdata", "clo_State.CDATA", "error", "end", "ready", "script", "opennamespace", "closenamespace" ];
});
$__jsx_lazy_init(_Common, "MAX_BUFFER_LENGTH", function () {
	return 64 * 1024;
});
_State.BEGIN = 1;
_State.TEXT = 2;
_State.TEXT_ENTITY = 3;
_State.OPEN_WAKA = 4;
_State.SGML_DECL = 5;
_State.SGML_DECL_QUOTED = 6;
_State.DOCTYPE = 7;
_State.DOCTYPE_QUOTED = 8;
_State.DOCTYPE_DTD = 9;
_State.DOCTYPE_DTD_QUOTED = 10;
_State.COMMENT_STARTING = 11;
_State.COMMENT = 12;
_State.COMMENT_ENDING = 13;
_State.COMMENT_ENDED = 14;
_State.CDATA = 15;
_State.CDATA_ENDING = 16;
_State.CDATA_ENDING_2 = 17;
_State.PROC_INST = 18;
_State.PROC_INST_BODY = 19;
_State.PROC_INST_ENDING = 20;
_State.OPEN_TAG = 21;
_State.OPEN_TAG_SLASH = 22;
_State.ATTRIB = 23;
_State.ATTRIB_NAME = 24;
_State.ATTRIB_NAME_SAW_WHITE = 25;
_State.ATTRIB_VALUE = 26;
_State.ATTRIB_VALUE_QUOTED = 27;
_State.ATTRIB_VALUE_UNQUOTED = 28;
_State.ATTRIB_VALUE_ENTITY_Q = 29;
_State.ATTRIB_VALUE_ENTITY_U = 30;
_State.CLOSE_TAG = 31;
_State.CLOSE_TAG_SAW_WHITE = 32;
_State.SCRIPT = 33;
_State.SCRIPT_ENDING = 34;
$__jsx_lazy_init(_Entities, "_entities", function () {
	return ({ "amp": "&", "gt": ">", "lt": "<", "quot": "\"", "apos": "'", "AElig": 198, "Aacute": 193, "Acirc": 194, "Agrave": 192, "Aring": 197, "Atilde": 195, "Auml": 196, "Ccedil": 199, "ETH": 208, "Eacute": 201, "Ecirc": 202, "Egrave": 200, "Euml": 203, "Iacute": 205, "Icirc": 206, "Igrave": 204, "Iuml": 207, "Ntilde": 209, "Oacute": 211, "Ocirc": 212, "Ograve": 210, "Oslash": 216, "Otilde": 213, "Ouml": 214, "THORN": 222, "Uacute": 218, "Ucirc": 219, "Ugrave": 217, "Uuml": 220, "Yacute": 221, "aacute": 225, "acirc": 226, "aelig": 230, "agrave": 224, "aring": 229, "atilde": 227, "auml": 228, "ccedil": 231, "eacute": 233, "ecirc": 234, "egrave": 232, "eth": 240, "euml": 235, "iacute": 237, "icirc": 238, "igrave": 236, "iuml": 239, "ntilde": 241, "oacute": 243, "ocirc": 244, "ograve": 242, "oslash": 248, "otilde": 245, "ouml": 246, "szlig": 223, "thorn": 254, "uacute": 250, "ucirc": 251, "ugrave": 249, "uuml": 252, "yacute": 253, "yuml": 255, "copy": 169, "reg": 174, "nbsp": 160, "iexcl": 161, "cent": 162, "pound": 163, "curren": 164, "yen": 165, "brvbar": 166, "sect": 167, "uml": 168, "ordf": 170, "laquo": 171, "not": 172, "shy": 173, "macr": 175, "deg": 176, "plusmn": 177, "sup1": 185, "sup2": 178, "sup3": 179, "acute": 180, "micro": 181, "para": 182, "middot": 183, "cedil": 184, "ordm": 186, "raquo": 187, "frac14": 188, "frac12": 189, "frac34": 190, "iquest": 191, "times": 215, "divide": 247, "OElig": 338, "oelig": 339, "Scaron": 352, "scaron": 353, "Yuml": 376, "fnof": 402, "circ": 710, "tilde": 732, "Alpha": 913, "Beta": 914, "Gamma": 915, "Delta": 916, "Epsilon": 917, "Zeta": 918, "Eta": 919, "Theta": 920, "Iota": 921, "Kappa": 922, "Lambda": 923, "Mu": 924, "Nu": 925, "Xi": 926, "Omicron": 927, "Pi": 928, "Rho": 929, "Sigma": 931, "Tau": 932, "Upsilon": 933, "Phi": 934, "Chi": 935, "Psi": 936, "Omega": 937, "alpha": 945, "beta": 946, "gamma": 947, "delta": 948, "epsilon": 949, "zeta": 950, "eta": 951, "theta": 952, "iota": 953, "kappa": 954, "lambda": 955, "mu": 956, "nu": 957, "xi": 958, "omicron": 959, "pi": 960, "rho": 961, "sigmaf": 962, "sigma": 963, "tau": 964, "upsilon": 965, "phi": 966, "chi": 967, "psi": 968, "omega": 969, "thetasym": 977, "upsih": 978, "piv": 982, "ensp": 8194, "emsp": 8195, "thinsp": 8201, "zwnj": 8204, "zwj": 8205, "lrm": 8206, "rlm": 8207, "ndash": 8211, "mdash": 8212, "lsquo": 8216, "rsquo": 8217, "sbquo": 8218, "ldquo": 8220, "rdquo": 8221, "bdquo": 8222, "dagger": 8224, "Dagger": 8225, "bull": 8226, "hellip": 8230, "permil": 8240, "prime": 8242, "Prime": 8243, "lsaquo": 8249, "rsaquo": 8250, "oline": 8254, "frasl": 8260, "euro": 8364, "image": 8465, "weierp": 8472, "real": 8476, "trade": 8482, "alefsym": 8501, "larr": 8592, "uarr": 8593, "rarr": 8594, "darr": 8595, "harr": 8596, "crarr": 8629, "lArr": 8656, "uArr": 8657, "rArr": 8658, "dArr": 8659, "hArr": 8660, "forall": 8704, "part": 8706, "exist": 8707, "empty": 8709, "nabla": 8711, "isin": 8712, "notin": 8713, "ni": 8715, "prod": 8719, "sum": 8721, "minus": 8722, "lowast": 8727, "radic": 8730, "prop": 8733, "infin": 8734, "ang": 8736, "and": 8743, "or": 8744, "cap": 8745, "cup": 8746, "int": 8747, "there4": 8756, "sim": 8764, "cong": 8773, "asymp": 8776, "ne": 8800, "equiv": 8801, "le": 8804, "ge": 8805, "sub": 8834, "sup": 8835, "nsub": 8836, "sube": 8838, "supe": 8839, "oplus": 8853, "otimes": 8855, "perp": 8869, "sdot": 8901, "lceil": 8968, "rceil": 8969, "lfloor": 8970, "rfloor": 8971, "lang": 9001, "rang": 9002, "loz": 9674, "spades": 9824, "clubs": 9827, "hearts": 9829, "diams": 9830 });
});
BitVector.SMALL_BLOCK_SIZE = 32;
BitVector.LARGE_BLOCK_SIZE = 256;
BitVector.BLOCK_RATE = 8;
$__jsx_lazy_init(BurrowsWheelerTransform, "END_MARKER", function () {
	return String.fromCharCode(0);
});
var $__jsx_classMap = {
	"tool/web/oktavia-english-search.jsx": {
		_Main: _Main,
		_Main$: _Main$
	},
	"tool/web/oktavia-search.jsx": {
		_Result: _Result,
		_Result$SSSI: _Result$SSSI,
		_Proposal: _Proposal,
		_Proposal$SSI: _Proposal$SSI,
		OktaviaSearch: OktaviaSearch,
		OktaviaSearch$I: OktaviaSearch$I,
		_Main: _Main$0,
		_Main$: _Main$0$
	},
	"src/oktavia.jsx": {
		Oktavia: Oktavia,
		Oktavia$: Oktavia$
	},
	"src/binary-util.jsx": {
		Binary: Binary,
		Binary$: Binary$,
		LoadedStringResult: LoadedStringResult,
		LoadedStringResult$SI: LoadedStringResult$SI,
		LoadedStringListResult: LoadedStringListResult,
		LoadedStringListResult$SI: LoadedStringListResult$SI,
		LoadedStringListMapResult: LoadedStringListMapResult,
		LoadedStringListMapResult$SI: LoadedStringListMapResult$SI,
		LoadedNumberListResult: LoadedNumberListResult,
		LoadedNumberListResult$SI: LoadedNumberListResult$SI,
		CompressionReport: CompressionReport,
		CompressionReport$: CompressionReport$
	},
	"src/query.jsx": {
		Query: Query,
		Query$: Query$
	},
	"src/query-string-parser.jsx": {
		QueryStringParser: QueryStringParser,
		QueryStringParser$: QueryStringParser$
	},
	"src/search-result.jsx": {
		Proposal: Proposal,
		Proposal$II: Proposal$II,
		Position: Position,
		Position$SIB: Position$SIB,
		SearchUnit: SearchUnit,
		SearchUnit$I: SearchUnit$I,
		SingleResult: SingleResult,
		SingleResult$: SingleResult$,
		SingleResult$SBB: SingleResult$SBB,
		SearchSummary: SearchSummary,
		SearchSummary$: SearchSummary$,
		SearchSummary$LOktavia$: SearchSummary$LOktavia$
	},
	"src/style.jsx": {
		Style: Style,
		Style$S: Style$S,
		_HTMLHandler: _HTMLHandler,
		_HTMLHandler$HASB: _HTMLHandler$HASB
	},
	"src/stemmer/stemmer.jsx": {
		Stemmer: Stemmer,
		Stemmer$: Stemmer$
	},
	"src/stemmer/base-stemmer.jsx": {
		BaseStemmer: BaseStemmer,
		BaseStemmer$: BaseStemmer$
	},
	"src/stemmer/english-stemmer.jsx": {
		EnglishStemmer: EnglishStemmer,
		EnglishStemmer$: EnglishStemmer$
	},
	"src/stemmer/among.jsx": {
		Among: Among,
		Among$SII: Among$SII,
		Among$SIIF$LBaseStemmer$B$LBaseStemmer$: Among$SIIF$LBaseStemmer$B$LBaseStemmer$
	},
	"src/metadata.jsx": {
		Metadata: Metadata,
		Metadata$LOktavia$: Metadata$LOktavia$,
		Section: Section,
		Section$LOktavia$: Section$LOktavia$,
		Splitter: Splitter,
		Splitter$LOktavia$: Splitter$LOktavia$,
		Splitter$LOktavia$S: Splitter$LOktavia$S,
		Table: Table,
		Table$LOktavia$AS: Table$LOktavia$AS,
		Block: Block,
		Block$LOktavia$: Block$LOktavia$
	},
	"src/fm-index.jsx": {
		FMIndex: FMIndex,
		FMIndex$: FMIndex$
	},
	"src/sax.jsx": {
		Tag: Tag,
		Tag$S: Tag$S,
		_Common: _Common,
		_Common$: _Common$,
		_State: _State,
		_State$: _State$,
		SAXHandler: SAXHandler,
		SAXHandler$: SAXHandler$,
		SAXParser: SAXParser,
		SAXParser$LSAXHandler$: SAXParser$LSAXHandler$,
		SAXParser$LSAXHandler$B: SAXParser$LSAXHandler$B,
		Char: Char,
		Char$: Char$,
		_Entities: _Entities,
		_Entities$: _Entities$
	},
	"src/bit-vector.jsx": {
		BitVector: BitVector,
		BitVector$: BitVector$
	},
	"src/wavelet-matrix.jsx": {
		WaveletMatrix: WaveletMatrix,
		WaveletMatrix$: WaveletMatrix$
	},
	"src/burrows-wheeler-transform.jsx": {
		BurrowsWheelerTransform: BurrowsWheelerTransform,
		BurrowsWheelerTransform$: BurrowsWheelerTransform$
	},
	"src/sais.jsx": {
		OArray: OArray,
		OArray$AI: OArray$AI,
		OArray$AII: OArray$AII,
		SAIS: SAIS,
		SAIS$: SAIS$
	}
};


/**
 * launches _Main.main(:string[]):void invoked by jsx --run|--executable
 */
JSX.runMain = function (sourceFile, args) {
	var module = JSX.require(sourceFile);
	if (! module) {
		throw new ReferenceError("entry point module not found in " + sourceFile);
	}
	if (! module._Main) {
		throw new ReferenceError("entry point _Main not found in " + sourceFile);
	}
	if (! module._Main.main$AS) {
		throw new ReferenceError("entry point _Main.main(:string[]):void not found in " + sourceFile);
	}
	module._Main.main$AS(args);
};

/**
 * launches _Test#test*():void invoked by jsx --test
 */
JSX.runTests = function (sourceFile, tests) {
	var module = JSX.require(sourceFile);
	var testClass = module._Test$;

	if (!testClass) return; // skip if there's no test class

	if(tests.length === 0) {
		var p = testClass.prototype;
		for (var m in p) {
			if (p[m] instanceof Function
				&& /^test.*[$]$/.test(m)) {
				tests.push(m);
			}
		}
	}
	else { // set as process arguments
		tests = tests.map(function (name) {
			return name + "$"; // mangle for function test*():void
		});
	}

	var testCase = new testClass();

	if (testCase.beforeClass$AS != null)
		testCase.beforeClass$AS(tests);

	for (var i = 0; i < tests.length; ++i) {
		(function (method) {
			if (method in testCase) {
				testCase.run$SF$V$(method, function() { testCase[method](); });
			}
			else {
				throw new ReferenceError("No such test method: " + method);
			}
		}(tests[i]));
	}

	if (testCase.afterClass$ != null)
		testCase.afterClass$();
};
/**
 * call a function on load/DOMContentLoaded
 */
function $__jsx_onload (event) {
	window.removeEventListener("load", $__jsx_onload);
	document.removeEventListener("DOMContentLoaded", $__jsx_onload);
	JSX.runMain("tool/web/oktavia-english-search.jsx", [])
}

window.addEventListener("load", $__jsx_onload);
document.addEventListener("DOMContentLoaded", $__jsx_onload);

})(JSX);
