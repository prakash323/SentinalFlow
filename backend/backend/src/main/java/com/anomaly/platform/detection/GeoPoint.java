package com.anomaly.platform.detection;

import java.util.Optional;

/*
 * ============================================================
 * SELF-REPORTED LOCATION
 * ============================================================
 *
 * The only location this platform carries is the LOGIN/LOGOUT/PASSWORD_CHANGE
 * payload's `location` field, in the form `City|lat|lon`. It is produced by the
 * simulators; the physical collector performs NO geo-IP lookup and omits the
 * field entirely (see normalizer.py build_login_event: "Never included:
 * location (no geo-IP lookup performed in this phase)").
 *
 * So this is the event SOURCE's own claim about where it was, not a lookup this
 * platform performed. IMPOSSIBLE_TRAVEL is honest about that: it only ever
 * evaluates events that actually carry a parseable location, and it says so in
 * its evidence. Nothing is geocoded, inferred from an IP, or invented.
 */
public record GeoPoint(String city, double latitude, double longitude) {

    private static final double EARTH_RADIUS_KM = 6371.0088;

    /**
     * Parse `City|lat|lon`. Anything else - missing field, wrong shape,
     * unparseable numbers, out-of-range coordinates - is empty, never a guess.
     */
    public static Optional<GeoPoint> parse(String raw) {
        if (raw == null) {
            return Optional.empty();
        }
        String[] parts = raw.split("\\|");
        if (parts.length != 3) {
            return Optional.empty();
        }
        String city = parts[0].trim();
        if (city.isEmpty()) {
            return Optional.empty();
        }
        try {
            double lat = Double.parseDouble(parts[1].trim());
            double lon = Double.parseDouble(parts[2].trim());
            if (!Double.isFinite(lat) || !Double.isFinite(lon)) {
                return Optional.empty();
            }
            if (lat < -90.0 || lat > 90.0 || lon < -180.0 || lon > 180.0) {
                return Optional.empty();
            }
            return Optional.of(new GeoPoint(city, lat, lon));
        } catch (NumberFormatException ignored) {
            return Optional.empty();
        }
    }

    /** Great-circle distance in kilometres (haversine). Deterministic and dependency-free. */
    public double distanceKmTo(GeoPoint other) {
        double dLat = Math.toRadians(other.latitude - this.latitude);
        double dLon = Math.toRadians(other.longitude - this.longitude);
        double lat1 = Math.toRadians(this.latitude);
        double lat2 = Math.toRadians(other.latitude);

        double a = Math.pow(Math.sin(dLat / 2), 2)
                + Math.cos(lat1) * Math.cos(lat2) * Math.pow(Math.sin(dLon / 2), 2);
        return 2 * EARTH_RADIUS_KM * Math.asin(Math.min(1.0, Math.sqrt(a)));
    }

    /** Implied average speed in km/h over `seconds`. Empty when the interval is not positive. */
    public Optional<Double> impliedSpeedKmph(GeoPoint other, long seconds) {
        if (seconds <= 0) {
            return Optional.empty();
        }
        return Optional.of(distanceKmTo(other) / (seconds / 3600.0));
    }
}
