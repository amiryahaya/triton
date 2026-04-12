package scanner

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

// realK8sClientFactory implements k8sClientFactory using client-go.
// This is the ONLY file in the scanner package that imports k8s.io/*.
type realK8sClientFactory struct{}

// newRealK8sClient returns the production k8sClientFactory.
// Called by newRealK8sClientFactory() in k8s_live.go.
func newRealK8sClient() k8sClientFactory {
	return &realK8sClientFactory{}
}

// NewClient builds a kubernetes.Clientset from the supplied kubeconfig path and
// context name. If kubeconfig is empty, in-cluster configuration is used.
func (f *realK8sClientFactory) NewClient(kubeconfig, k8sContext string) (k8sClient, error) {
	var cfg *rest.Config
	var err error

	if kubeconfig != "" {
		loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfig}
		overrides := &clientcmd.ConfigOverrides{}
		if k8sContext != "" {
			overrides.CurrentContext = k8sContext
		}
		cfg, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
			loadingRules, overrides).ClientConfig()
	} else {
		cfg, err = rest.InClusterConfig()
	}
	if err != nil {
		return nil, fmt.Errorf("k8s config: %w", err)
	}

	clientset, err := kubernetes.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s clientset: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("k8s dynamic client: %w", err)
	}

	return &realK8sAPIClient{
		clientset: clientset,
		dynamic:   dynClient,
	}, nil
}

// realK8sAPIClient wraps kubernetes.Clientset and a dynamic.Interface to
// implement the k8sClient interface. The dynamic client is used for CRDs
// (cert-manager) which have no generated typed client in the core client-go.
type realK8sAPIClient struct {
	clientset *kubernetes.Clientset
	dynamic   dynamic.Interface
}

// ListTLSSecrets returns all kubernetes.io/tls secrets in the given namespace.
// Pass "" for namespace to list across all namespaces.
func (c *realK8sAPIClient) ListTLSSecrets(ctx context.Context, namespace string) ([]k8sTLSSecret, error) {
	opts := metav1.ListOptions{
		FieldSelector: "type=kubernetes.io/tls",
		Limit:         500,
	}
	list, err := c.clientset.CoreV1().Secrets(namespace).List(ctx, opts)
	if err != nil {
		return nil, err
	}
	out := make([]k8sTLSSecret, 0, len(list.Items))
	for _, s := range list.Items {
		out = append(out, k8sTLSSecret{
			Namespace: s.Namespace,
			Name:      s.Name,
			CertPEM:   s.Data[corev1.TLSCertKey],
			KeyPEM:    s.Data[corev1.TLSPrivateKeyKey],
		})
	}
	return out, nil
}

// ListIngresses returns Ingress resources that have at least one TLS block.
func (c *realK8sAPIClient) ListIngresses(ctx context.Context, namespace string) ([]k8sIngress, error) {
	list, err := c.clientset.NetworkingV1().Ingresses(namespace).List(ctx, metav1.ListOptions{Limit: 500})
	if err != nil {
		return nil, err
	}
	var out []k8sIngress
	for _, ing := range list.Items {
		var tlsHosts []k8sIngressTLS
		for _, tls := range ing.Spec.TLS {
			tlsHosts = append(tlsHosts, k8sIngressTLS{
				Hosts:      tls.Hosts,
				SecretName: tls.SecretName,
			})
		}
		if len(tlsHosts) > 0 {
			out = append(out, k8sIngress{
				Namespace: ing.Namespace,
				Name:      ing.Name,
				TLSHosts:  tlsHosts,
			})
		}
	}
	return out, nil
}

// ListWebhookConfigs returns ValidatingWebhookConfiguration and
// MutatingWebhookConfiguration resources that carry a non-empty CABundle.
// One k8sWebhookConfig is emitted per webhook resource (not per hook entry).
func (c *realK8sAPIClient) ListWebhookConfigs(ctx context.Context) ([]k8sWebhookConfig, error) {
	var out []k8sWebhookConfig

	valList, err := c.clientset.AdmissionregistrationV1().
		ValidatingWebhookConfigurations().List(ctx, metav1.ListOptions{Limit: 500})
	if err != nil {
		return nil, err
	}
	for _, wh := range valList.Items {
		for _, hook := range wh.Webhooks {
			if len(hook.ClientConfig.CABundle) > 0 {
				out = append(out, k8sWebhookConfig{
					Name:     wh.Name,
					Kind:     "ValidatingWebhookConfiguration",
					CABundle: hook.ClientConfig.CABundle,
				})
				break // one finding per webhook config object, not per hook entry
			}
		}
	}

	mutList, err := c.clientset.AdmissionregistrationV1().
		MutatingWebhookConfigurations().List(ctx, metav1.ListOptions{Limit: 500})
	if err != nil {
		return nil, err
	}
	for _, wh := range mutList.Items {
		for _, hook := range wh.Webhooks {
			if len(hook.ClientConfig.CABundle) > 0 {
				out = append(out, k8sWebhookConfig{
					Name:     wh.Name,
					Kind:     "MutatingWebhookConfiguration",
					CABundle: hook.ClientConfig.CABundle,
				})
				break
			}
		}
	}

	return out, nil
}

// ListConfigMaps returns ConfigMaps matching name that contain a "ca.crt" key.
func (c *realK8sAPIClient) ListConfigMaps(ctx context.Context, namespace, name string) ([]k8sConfigMap, error) {
	opts := metav1.ListOptions{
		FieldSelector: "metadata.name=" + name,
		Limit:         500,
	}
	list, err := c.clientset.CoreV1().ConfigMaps(namespace).List(ctx, opts)
	if err != nil {
		return nil, err
	}
	var out []k8sConfigMap
	for _, cm := range list.Items {
		if certData, ok := cm.Data["ca.crt"]; ok {
			out = append(out, k8sConfigMap{
				Namespace: cm.Namespace,
				Name:      cm.Name,
				CACertPEM: []byte(certData),
			})
		}
	}
	return out, nil
}

// cert-manager GroupVersionResources for dynamic listing.
var (
	certManagerCertGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "certificates",
	}
	certManagerIssuerGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "issuers",
	}
	certManagerClusterIssuerGVR = schema.GroupVersionResource{
		Group: "cert-manager.io", Version: "v1", Resource: "clusterissuers",
	}
)

// ListCertManagerCertificates lists cert-manager Certificate CRDs via the
// dynamic client and converts them to k8sCertManagerCert structs.
func (c *realK8sAPIClient) ListCertManagerCertificates(ctx context.Context, namespace string) ([]k8sCertManagerCert, error) {
	list, err := c.dynamic.Resource(certManagerCertGVR).Namespace(namespace).List(ctx, metav1.ListOptions{Limit: 500})
	if err != nil {
		return nil, err
	}
	var out []k8sCertManagerCert
	for _, item := range list.Items {
		spec, _ := item.Object["spec"].(map[string]interface{})
		if spec == nil {
			continue
		}
		cert := k8sCertManagerCert{
			Namespace: item.GetNamespace(),
			Name:      item.GetName(),
		}
		if secretName, ok := spec["secretName"].(string); ok {
			cert.SecretName = secretName
		}
		if pk, ok := spec["privateKey"].(map[string]interface{}); ok {
			if algo, ok := pk["algorithm"].(string); ok {
				cert.Algorithm = algo
			}
			if size, ok := pk["size"].(float64); ok {
				cert.KeySize = int(size)
			}
		}
		if issuerRef, ok := spec["issuerRef"].(map[string]interface{}); ok {
			if name, ok := issuerRef["name"].(string); ok {
				cert.IssuerRef = name
			}
		}
		out = append(out, cert)
	}
	return out, nil
}

// ListCertManagerIssuers lists cert-manager Issuer CRDs via the dynamic client.
func (c *realK8sAPIClient) ListCertManagerIssuers(ctx context.Context, namespace string) ([]k8sCertManagerIssuer, error) {
	list, err := c.dynamic.Resource(certManagerIssuerGVR).Namespace(namespace).List(ctx, metav1.ListOptions{Limit: 500})
	if err != nil {
		return nil, err
	}
	var out []k8sCertManagerIssuer
	for _, item := range list.Items {
		issuer := k8sCertManagerIssuer{
			Namespace: item.GetNamespace(),
			Name:      item.GetName(),
			Kind:      "Issuer",
		}
		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if ca, ok := spec["ca"].(map[string]interface{}); ok {
				if secret, ok := ca["secretName"].(string); ok {
					issuer.CASecret = secret
				}
			}
		}
		out = append(out, issuer)
	}
	return out, nil
}

// ListCertManagerClusterIssuers lists cert-manager ClusterIssuer CRDs (cluster-scoped).
func (c *realK8sAPIClient) ListCertManagerClusterIssuers(ctx context.Context) ([]k8sCertManagerIssuer, error) {
	// ClusterIssuers are cluster-scoped; use the non-namespaced resource interface.
	list, err := c.dynamic.Resource(certManagerClusterIssuerGVR).List(ctx, metav1.ListOptions{Limit: 500})
	if err != nil {
		return nil, err
	}
	var out []k8sCertManagerIssuer
	for _, item := range list.Items {
		issuer := k8sCertManagerIssuer{
			Name: item.GetName(),
			Kind: "ClusterIssuer",
		}
		if spec, ok := item.Object["spec"].(map[string]interface{}); ok {
			if ca, ok := spec["ca"].(map[string]interface{}); ok {
				if secret, ok := ca["secretName"].(string); ok {
					issuer.CASecret = secret
				}
			}
		}
		out = append(out, issuer)
	}
	return out, nil
}

// HasAPIGroup checks whether the given API group is registered in the cluster
// using the discovery client. This is used to gate cert-manager CRD listing.
func (c *realK8sAPIClient) HasAPIGroup(group string) (bool, error) {
	groups, err := c.clientset.Discovery().ServerGroups()
	if err != nil {
		return false, err
	}
	for _, g := range groups.Groups {
		if g.Name == group {
			return true, nil
		}
	}
	return false, nil
}
