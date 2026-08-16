/* Basket operations.
 *
 * POST to add and DELETE to remove, deliberately: a log whose verb column is
 * entirely GET is a log nobody can study method distribution in.
 */
(function () {
    "use strict";

    function count(n) {
        var badge = document.getElementById("cart-count");
        if (badge) {
            badge.textContent = String(n);
        }
    }

    function add(productId) {
        fetch("/api/cart", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ id: Number(productId), quantity: 1 })
        })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) { if (data) { count(data.count); } })
            .catch(function () { /* ignored */ });
    }

    document.addEventListener("click", function (event) {
        var button = event.target.closest ? event.target.closest("button.add") : null;
        if (button && button.dataset.product) {
            event.preventDefault();
            add(button.dataset.product);
        }
    });

    document.addEventListener("DOMContentLoaded", function () {
        fetch("/api/cart", { headers: { "Accept": "application/json" } })
            .then(function (r) { return r.ok ? r.json() : null; })
            .then(function (data) { if (data) { count(data.count); } })
            .catch(function () { /* ignored */ });
    });
}());
