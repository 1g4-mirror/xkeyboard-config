<xsl:stylesheet version="1.0"
    xmlns:xsl="http://www.w3.org/1999/XSL/Transform"
    xmlns:ns="some:ns">
    <xsl:output
        omit-xml-declaration="no"
        indent="yes"
        encoding="utf-8"
        doctype-system="xkb.dtd"
    />
    <xsl:strip-space elements="*"/>

    <xsl:template match="node()|@*">
        <xsl:copy>
            <xsl:apply-templates select="node()|@*"/>
        </xsl:copy>
    </xsl:template>

    <!-- Tags to remove -->
    <xsl:template match="header"/>
    <xsl:template match="*/membership"/>
    <xsl:template match="*/member-of"/>
    <xsl:template match="*/aliases"/>
    <xsl:template match="*/alias"/>
    <xsl:template match="*/rules"/>
    <xsl:template match="*/rule"/>
    <xsl:template match="//*[@disabled='true']"/>

    <!-- Attributes to remove -->
    <xsl:template match="@priority"/>
    <xsl:template match="@rules"/>
    <xsl:template match="@category"/>
</xsl:stylesheet>
