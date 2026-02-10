package io.dodn.springboot.core.api.controller;

import io.dodn.springboot.core.domain.pki.cmp.service.CmpRequestProcessor;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/pki")
public class CmpController {

    private static final String PKIXCMP_MEDIA_TYPE = "application/pkixcmp";

    private final CmpRequestProcessor cmpRequestProcessor;

    public CmpController(CmpRequestProcessor cmpRequestProcessor) {
        this.cmpRequestProcessor = cmpRequestProcessor;
    }

    @PostMapping(value = "/{caAlias}",
            consumes = PKIXCMP_MEDIA_TYPE,
            produces = PKIXCMP_MEDIA_TYPE)
    public ResponseEntity<byte[]> handleCmpRequest(
            @PathVariable String caAlias,
            @RequestBody byte[] derPkiMessage) {
        byte[] response = cmpRequestProcessor.process(derPkiMessage, caAlias);
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType(PKIXCMP_MEDIA_TYPE))
                .body(response);
    }
}
