<?php
/**
 * When a product page shows the low-stock badge.
 *
 * One place, because two things depend on it: the product page marks the
 * badge, and the seeder publishes the products that have it in
 * catalogue.json for the driver, which plans the page script's calls.
 */

const LOW_STOCK = 5;
