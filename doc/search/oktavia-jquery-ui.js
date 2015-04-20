$(document).ready(function ()
{
    // it stores search object
    var searchInstance;

    function changePage(event)
    {
        searchInstance.setCurrentPage$I(event.data);
        updateResult();
    }

    function clearResult()
    {
        $('#search').val('');
        $('#searchresult_box').fadeOut();
    }

    // http://os0x.hatenablog.com/entry/20080827/1219815828
    function JavaScriptLoader(src, callback)
    {
        var sc = document.createElement('script');
        sc.type = 'text/javascript';
        if (window.ActiveXObject)
        {
            sc.onreadystatechange = function()
            {
                if (sc.readyState == 'complete' || sc.readyState == 'loaded')
                {
                    callback(sc.readyState);
                }
            };
        }
        else
        {
            sc.onload = function()
            {
                callback('onload');
            };
        }
        sc.src = src;
        document.body.appendChild(sc);
    }

    function updateResult()
    {
        var totalPages = searchInstance.totalPages$();
        var currentPage = searchInstance.currentPage$();
        var nav = $('#searchresult_nav');
        var resultslot = $('#searchresult');
        nav.empty();
        resultslot.empty();
        var i;
        for (i = 1; i <= totalPages; i++)
        {
            var pageItem = $('<span/>').text(i);
            if (i !== currentPage)
            {
                pageItem.bind('click', i, changePage);
            }
            else
            {
                pageItem.addClass('selected');
            }
            nav.append(pageItem);
        }
        var results = searchInstance.getResult$();
        for (i = 0; i < results.length; i++)
        {
            var result = results[i];
            var url = result.url.slice(1);
            var entry = $('<div/>', { "class": "entry" });
            var link = $('<a/>', { "href": url }).text(result.title);
            link.on('click', clearResult);
            entry.append($('<div/>', { "class": "title" }).append(link));
            entry.append($('<div/>', { "class": "url" }).text(url));
            entry.append($('<div/>', { "class": "content" }).html(result.content));
            resultslot.append(entry);
        }
    }

    function searchProposal(event)
    {
        $('#search').val(event.data.option);
        search();
    }

    function updateProposal()
    {
        var nav = $('#searchresult_nav');
        var resultslot = $('#searchresult');
        nav.empty();
        resultslot.empty();
        var proposals = searchInstance.getProposals$();
        for (var i = 0; i < proposals.length; i++)
        {
            var proposal = proposals[i];
            var listitem = $('<div/>', {"class": "proposal"});
            listitem.append('<span>Search with:&nbsp;</span>');
            var option = $('<span/>', {"class": "option"});
            option.html(proposal.label);
            option.on('click', {'option': proposal.options}, searchProposal);
            listitem.append(option);
            listitem.append('<span>&nbsp;&#x2192;&nbsp;' + proposal.count + ' results.</span>');
            resultslot.append(listitem);
        }
    }

    function search ()
    {
        var queryWord = $('#search').val();
        searchInstance.search$SF$IIV$(queryWord, function (total, pages)
        {
            $('#searchresult_box').fadeIn();
            console.log("Total: ", total);
            if (total === 0)
            {
                $('#searchresult_summary').text("No result.");
                updateProposal();
            }
            else
            {
                $('#searchresult_summary').text(total + ' results.');
                updateResult();
            }
        });
    }

    // initialize function
    function initialize ()
    {
        if (!searchInstance)
        {
            var OktaviaSearch = JSX.require("tool/web/oktavia-search.jsx").OktaviaSearch$I;
            searchInstance = new OktaviaSearch(5);
        }
        JavaScriptLoader('search/searchindex.js', function ()
        {
            searchInstance.loadIndex$S(searchIndex);
            searchIndex = null;
        });
        $('#searchform').on('submit', function (event) {
            event.stopPropagation();
            setTimeout(search, 10);
            return false;
        });
        $('#close_search_box').on('click', function (event) {
            clearResult();
        });
    }
    initialize();
});

/*function keyboardHook(event)
{
    if (event.keyCode === 191 && document.activeElement.id !== searchBoxId) // slash
    {
        document.getElementById(searchBoxId).focus();
    }
}

if (window.addEventListener)
{
    window.addEventListener('load', initialize, false);
    document.addEventListener("keydown" , keyboardHook);
}
if (window.attachEvent)
{
    window.attachEvent('onload', initialize);
    document.attachEvent("onkeydown" , keyboardHook);
}

})();
});
*/

