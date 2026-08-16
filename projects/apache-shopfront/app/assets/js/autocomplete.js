/* Search suggestions.
 *
 * Types produce a run of short API calls in quick succession from one client,
 * which is a shape worth having in the data: it looks superficially like
 * enumeration and is not.
 */
(function () {
    "use strict";

    var box = document.getElementById("q");
    if (!box) {
        return;
    }

    var list = document.createElement("ul");
    list.className = "suggestions";
    list.hidden = true;
    box.parentNode.appendChild(list);

    var pending = null;

    function show(items) {
        list.innerHTML = "";
        items.slice(0, 8).forEach(function (item) {
            var li = document.createElement("li");
            li.textContent = item.name;
            list.appendChild(li);
        });
        list.hidden = items.length === 0;
    }

    box.addEventListener("input", function () {
        var q = box.value.trim();
        if (q.length < 2) {
            list.hidden = true;
            return;
        }
        window.clearTimeout(pending);
        pending = window.setTimeout(function () {
            fetch("/api/autocomplete?q=" + encodeURIComponent(q), {
                headers: { "Accept": "application/json" }
            })
                .then(function (r) { return r.ok ? r.json() : null; })
                .then(function (data) { if (data) { show(data.matches || []); } })
                .catch(function () { /* ignored */ });
        }, 140);
    });
}());
