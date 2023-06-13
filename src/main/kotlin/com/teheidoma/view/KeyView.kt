package com.teheidoma.view

import com.google.gson.Gson
import com.google.gson.JsonObject
import javafx.beans.property.SimpleObjectProperty
import javafx.geometry.Orientation
import javafx.util.StringConverter
import org.jose4j.base64url.Base64
import org.jose4j.jwk.JsonWebKey
import tornadofx.*
import java.security.*
import java.security.spec.ECGenParameterSpec

class KeyView : View("KeyView") {
    private val keypair = SimpleObjectProperty<KeyPair>()
    private val privateKeyProperty = SimpleObjectProperty<PrivateKey>()
    private val publicKeyProperty = SimpleObjectProperty<PublicKey>()
    private val serverPrivateKeyProperty = SimpleObjectProperty<PrivateKey>()
    private val serverPublicKeyProperty = SimpleObjectProperty<PublicKey>()

    override val root = vbox {

        hbox {
            label("private")
            textarea(privateKeyProperty, converter = KeyConverter(true)) {
                isWrapText = true
            }
            textarea(privateKeyProperty, converter = KeyConverter(false)) {
                isWrapText = true
            }
        }
        hbox {
            label("public")
            textarea(publicKeyProperty, converter = KeyConverter(true)) {
                isWrapText = true
            }
            textarea(publicKeyProperty, converter = KeyConverter(false)) {
                isWrapText = true
            }
            textarea(publicKeyProperty, converter = LambdaConverter<PublicKey> {
                val gson = Gson()
                val jsonObject = JsonObject()
                val json = gson.toJsonTree(JsonWebKey.Factory.newJwk(it).toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE))
                jsonObject.addProperty("deviceType", "WEB")
                jsonObject.add("clientPublicKey", json)
                gson.toJson(jsonObject)
            })
        }
        button("generate") {
            action {
                val generator = KeyPairGenerator.getInstance("EC")
                generator.initialize(ECGenParameterSpec("secp384r1"), SecureRandom())
                keypair.set(generator.generateKeyPair())
            }
        }
        separator(Orientation.HORIZONTAL)
        hbox {
            label("private")
            textarea(serverPrivateKeyProperty, converter = KeyConverter(true)) {
                isWrapText = true
            }
            textarea(serverPrivateKeyProperty, converter = KeyConverter(false)) {
                isWrapText = true
            }
        }
        hbox {
            label("public")
            textarea(serverPublicKeyProperty, converter = KeyConverter(true)) {
                isWrapText = true
            }
            textarea(serverPublicKeyProperty, converter = KeyConverter(false)) {
                isWrapText = true
            }
            textarea(serverPublicKeyProperty, converter = LambdaConverter<PublicKey> {
                val gson = Gson()
                val jsonObject = JsonObject()
                val json = gson.toJsonTree(JsonWebKey.Factory.newJwk(it).toParams(JsonWebKey.OutputControlLevel.INCLUDE_PRIVATE))
                jsonObject.addProperty("deviceType", "WEB")
                jsonObject.add("clientPublicKey", json)
                gson.toJson(jsonObject)
            })
        }
    }

    init {
        keypair.onChange {
            privateKeyProperty.set(it?.private)
            publicKeyProperty.set(it?.public)
        }
    }


}

class LambdaConverter<T>(private val op: (T) -> String) : StringConverter<T>() {
    override fun toString(p0: T): String {
        return if (p0 != null) {
            op.invoke(p0)
        } else {
            ""
        }
    }

    override fun fromString(p0: String?): T {
        TODO("Not yet implemented")
    }

}

class KeyConverter<T : Key>(val base64: Boolean = false) : StringConverter<T>() {
    override fun toString(p0: T?): String {
        return if (p0 != null) {
            if (base64) {
                Base64.encode(p0.encoded)
            } else {
                JsonWebKey.Factory.newJwk(p0).toJson()
            }
        } else {
            ""
        }
    }

    override fun fromString(p0: String?): T {
        return if (p0 != null && p0.isNotBlank()) {
            JsonWebKey.Factory.newJwk(p0.replace(Regex.fromLiteral("\\\""), "\"")).key as T
        } else {
            null!!
        }
    }
}
