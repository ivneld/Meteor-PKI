package io.dodn.springboot.core.api.controller.v1;

import io.dodn.springboot.core.api.controller.v1.request.CreateRootCaRequest;
import io.dodn.springboot.core.api.controller.v1.request.CreateSubCaRequest;
import io.dodn.springboot.core.api.controller.v1.response.CaResponse;
import io.dodn.springboot.core.domain.pki.ca.CertificateAuthority;
import io.dodn.springboot.core.domain.pki.ca.service.CaManagementService;
import io.dodn.springboot.core.domain.pki.vo.CaId;
import io.dodn.springboot.core.support.response.ApiResponse;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/v1/pki/ca")
public class CaManagementController {

    private final CaManagementService caManagementService;

    public CaManagementController(CaManagementService caManagementService) {
        this.caManagementService = caManagementService;
    }

    @PostMapping("/root")
    public ApiResponse<CaResponse> createRootCa(@RequestBody CreateRootCaRequest request) {
        CertificateAuthority ca = caManagementService.createRootCa(request.toCommand());
        return ApiResponse.success(CaResponse.from(ca));
    }

    @PostMapping
    public ApiResponse<CaResponse> createSubCa(@RequestBody CreateSubCaRequest request) {
        CertificateAuthority ca = caManagementService.createSubCa(request.toCommand());
        return ApiResponse.success(CaResponse.from(ca));
    }

    @GetMapping
    public ApiResponse<List<CaResponse>> listCas() {
        List<CaResponse> responses = caManagementService.findAll().stream()
                .map(CaResponse::from).toList();
        return ApiResponse.success(responses);
    }

    @GetMapping("/{id}")
    public ApiResponse<CaResponse> getCa(@PathVariable Long id) {
        CertificateAuthority ca = caManagementService.findById(CaId.of(id));
        return ApiResponse.success(CaResponse.from(ca));
    }

    @GetMapping("/{id}/certificate")
    public ResponseEntity<String> getCertificate(@PathVariable Long id) {
        CertificateAuthority ca = caManagementService.findById(CaId.of(id));
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/x-pem-file"))
                .body(ca.getCertificate().pem());
    }

    @GetMapping("/{id}/chain")
    public ApiResponse<List<String>> getCaChain(@PathVariable Long id) {
        List<String> chain = caManagementService.getCaChain(CaId.of(id)).stream()
                .map(ca -> ca.getCertificate().pem())
                .toList();
        return ApiResponse.success(chain);
    }

    @GetMapping("/{id}/crl")
    public ResponseEntity<byte[]> getCrl(@PathVariable Long id) {
        byte[] crl = caManagementService.generateCrl(CaId.of(id));
        return ResponseEntity.ok()
                .contentType(MediaType.parseMediaType("application/pkix-crl"))
                .header(HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=crl.crl")
                .body(crl);
    }
}
