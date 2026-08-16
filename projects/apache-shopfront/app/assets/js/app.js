/* Front-end bootstrap.
 *
 * The XHR calls these scripts make are why api_call lines appear interleaved
 * with page views in the log rather than in a separate block. A browser
 * session that never calls an API looks nothing like a real one.
 */
(function () {
    "use strict";

    function refreshStock() {
        var el = document.querySelector(".stock[data-product]");
        if (!el) {
            return;
        }
        fetch("/api/stock?id=" + encodeURIComponent(el.dataset.product), {
            headers: { "Accept": "application/json" }
        })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) {
                if (data && typeof data.stock === "number") {
                    el.textContent = data.stock + " in stock";
                }
            })
            .catch(function () { /* the log line is the point, not the update */ });
    }

    document.addEventListener("DOMContentLoaded", refreshStock);
}());
