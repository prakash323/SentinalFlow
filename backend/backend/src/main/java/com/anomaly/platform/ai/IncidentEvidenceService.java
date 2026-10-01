package com.anomaly.platform.ai;

import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.AlertFactor;
import com.anomaly.platform.entity.Event;
import com.anomaly.platform.entity.Incident;
import com.anomaly.platform.entity.Prediction;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.repository.AlertFactorRepository;
import com.anomaly.platform.repository.AlertRepository;
import com.anomaly.platform.repository.IncidentRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.UUID;

/*
 * ================================================================
 * READ-ONLY EVIDENCE ASSEMBLY FOR THE AI ANALYST-ASSISTANCE LAYER
 * ================================================================
 *
 * This is the ONLY component in Phase 6 that touches a repository. It
 * assembles a structured, immutable IncidentEvidence snapshot from
 * already-computed SentinelFlow data (the incident, its alerts, their
 * factors, and the originating prediction's ML output) and hands that
 * plain record to IncidentAiService, which has no repository access of
 * its own.
 *
 * Every method here is @Transactional(readOnly = true) - nothing in this
 * class ever calls save()/delete() on anything, so an AI failure
 * downstream cannot mutate incident/alert state: there is no write path
 * for it to reach even if it wanted to.
 */
@Service
public class IncidentEvidenceService {

    private final IncidentRepository incidentRepository;
    private final AlertRepository alertRepository;
    private final AlertFactorRepository alertFactorRepository;

    public IncidentEvidenceService(
            IncidentRepository incidentRepository,
            AlertRepository alertRepository,
            AlertFactorRepository alertFactorRepository
    ) {
        this.incidentRepository = incidentRepository;
        this.alertRepository = alertRepository;
        this.alertFactorRepository = alertFactorRepository;
    }

    @Transactional(readOnly = true)
    public IncidentEvidence gather(UUID incidentId) {

        Incident incident =
                incidentRepository.findById(incidentId)
                        .orElseThrow(() ->
                                new NotFoundException("Incident not found: " + incidentId)
                        );

        List<Alert> alerts =
                alertRepository.findByIncident_IdOrderByCreatedAtDesc(incidentId);

        List<AlertEvidence> alertEvidence =
                alerts.stream()
                        .map(this::toAlertEvidence)
                        .toList();

        return new IncidentEvidence(
                incident.getId().toString(),
                incident.getIncidentKey(),
                incident.getEntity() == null ? null : incident.getEntity().getEntityId(),
                incident.getStatus() == null ? null : incident.getStatus().name(),
                incident.getSummary(),
                incident.getCreatedAt(),
                incident.getUpdatedAt(),
                incident.getClosedAt(),
                alertEvidence
        );
    }

    /*
     * Public (not private) so AlertAiEvidenceService maps a single alert with
     * exactly the same rules - factors, attackType and reason from the
     * originating prediction - instead of keeping a second copy. Must be
     * called inside a read-only transaction (both callers are): it walks
     * lazy associations.
     */
    public AlertEvidence toAlertEvidence(Alert alert) {

        List<String> factors =
                alertFactorRepository.findByAlert_IdOrderByRankAsc(alert.getId())
                        .stream()
                        .map(AlertFactor::getFactor)
                        .toList();

        String attackType = null;
        String mlReason = null;

        Prediction prediction = alert.getPrediction();

        if (prediction != null && prediction.getFeatures() != null) {

            Object attackTypeValue = prediction.getFeatures().get("attackType");
            Object reasonValue = prediction.getFeatures().get("reason");

            attackType = attackTypeValue == null ? null : String.valueOf(attackTypeValue);
            mlReason = reasonValue == null ? null : String.valueOf(reasonValue);
        }

        Event event = alert.getEvent();

        return new AlertEvidence(
                alert.getId().toString(),
                event == null ? null : event.getEventId(),
                event == null ? null : event.getEventType(),
                event == null ? null : event.getOccurredAt(),
                alert.getDecision() == null ? null : alert.getDecision().name(),
                alert.getSeverity() == null ? null : alert.getSeverity().name(),
                alert.getStatus() == null ? null : alert.getStatus().name(),
                alert.getAnomalyScore(),
                alert.getConfidence(),
                alert.getFusedScore(),
                alert.getPolicyVersion(),
                factors,
                attackType,
                mlReason,
                alert.getCreatedAt()
        );
    }
}
