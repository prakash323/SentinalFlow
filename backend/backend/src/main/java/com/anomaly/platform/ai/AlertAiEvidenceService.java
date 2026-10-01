package com.anomaly.platform.ai;

import com.anomaly.platform.entity.Alert;
import com.anomaly.platform.entity.Incident;
import com.anomaly.platform.exception.NotFoundException;
import com.anomaly.platform.repository.AlertRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.UUID;

/*
 * READ-ONLY EVIDENCE ASSEMBLY FOR THE ALERT ASSISTANT
 *
 * The alert counterpart of IncidentEvidenceService: the only place the alert
 * assistant's inputs touch a repository. It is @Transactional(readOnly = true)
 * and never calls save()/delete(), so an AI failure downstream has no write
 * path to alert or incident state.
 */
@Service
public class AlertAiEvidenceService {

    private final AlertRepository alertRepository;
    private final IncidentEvidenceService incidentEvidenceService;

    public AlertAiEvidenceService(
            AlertRepository alertRepository,
            IncidentEvidenceService incidentEvidenceService
    ) {
        this.alertRepository = alertRepository;
        this.incidentEvidenceService = incidentEvidenceService;
    }

    @Transactional(readOnly = true)
    public AlertAiEvidence gather(UUID alertId) {

        Alert alert =
                alertRepository.findById(alertId)
                        .orElseThrow(() ->
                                new NotFoundException("Alert not found: " + alertId)
                        );

        Incident incident = alert.getIncident();

        Integer incidentAlertCount =
                incident == null
                        ? null
                        : alertRepository.findByIncident_IdOrderByCreatedAtDesc(incident.getId()).size();

        return new AlertAiEvidence(
                incidentEvidenceService.toAlertEvidence(alert),
                alert.getEntity() == null ? null : alert.getEntity().getEntityId(),
                alert.getEvent() == null ? null : alert.getEvent().getSource(),
                incident == null ? null : incident.getId().toString(),
                incident == null ? null : incident.getIncidentKey(),
                incident == null || incident.getStatus() == null ? null : incident.getStatus().name(),
                incident == null ? null : incident.getSummary(),
                incidentAlertCount
        );
    }
}
