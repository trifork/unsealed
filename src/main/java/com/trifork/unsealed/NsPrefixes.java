package com.trifork.unsealed;

enum NsPrefixes {
	ds(XmlUtil.DSIG_SCHEMA), saml(XmlUtil.SAML2ASSERTION_SCHEMA), xsi(XmlUtil.XMLSCHEMAINSTANCE_SCHEMA),
	medcom(XmlUtil.MEDCOM_SCHEMA), wsp(XmlUtil.WSP_SCHEMA), wsse(XmlUtil.WSSE_SCHEMA), wst(XmlUtil.WST_SCHEMA),
	wst13(XmlUtil.WST_1_3_SCHEMA), wst14(XmlUtil.WST_1_4_SCHEMA), wsu(XmlUtil.WSU_SCHEMA),
	sosi(XmlUtil.SOSI_SCHEMA), xsd(XmlUtil.XSD_SCHEMA), soap(XmlUtil.SOAP_ENV), wsa(XmlUtil.WSA_1_0_SCHEMA), auth(XmlUtil.WSF_AUTH_SCHEMA), 
	xenc(XmlUtil.XENC), bpp(XmlUtil.BPP);

	public final String namespaceUri;

	NsPrefixes(String namespaceUri) {
		this.namespaceUri = namespaceUri;
	}
}