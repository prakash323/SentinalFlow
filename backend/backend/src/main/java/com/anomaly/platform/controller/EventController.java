package com.anomaly.platform.controller;

import com.anomaly.platform.dto.CreateEventRequest;
import com.anomaly.platform.dto.EventResponse;
import com.anomaly.platform.dto.EventTrailResponse;
import com.anomaly.platform.dto.PageResponse;
import com.anomaly.platform.service.EventService;

import jakarta.validation.Valid;

import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@RestController
@RequestMapping("/api/v1/events")
public class EventController {

    private final EventService service;

    public EventController(
            EventService service
    ) {
        this.service = service;
    }

    /*
     * ============================================================
     * CREATE EVENT
     * ============================================================
     */

    @PostMapping
    @ResponseStatus(HttpStatus.CREATED)
    public EventResponse create(
            @Valid
            @RequestBody
            CreateEventRequest request
    ) {

        return service.create(
                request
        );
    }

    /*
     * ============================================================
     * LIST EVENTS
     * ============================================================
     */

    @GetMapping
    public PageResponse<EventResponse> list(
            @RequestParam(required = false)
            String entityId,

            @RequestParam(required = false)
            String eventType,

            @RequestParam(required = false)
            String source,

            @RequestParam(defaultValue = "0")
            int page,

            @RequestParam(defaultValue = "20")
            int size
    ) {

        return service.list(
                entityId,
                eventType,
                source,
                page,
                size
        );
    }

    /*
     * ============================================================
     * GET EVENT
     * ============================================================
     */

    @GetMapping("/{eventId}")
    public EventResponse get(
            @PathVariable String eventId
    ) {

        return service.get(
                eventId
        );
    }

    /*
     * ============================================================
     * EVENT PROCESSING TRAIL (prediction + alert for one event)
     * ============================================================
     */

    @GetMapping("/{eventId}/trail")
    public EventTrailResponse trail(
            @PathVariable String eventId
    ) {

        return service.trail(
                eventId
        );
    }
}
