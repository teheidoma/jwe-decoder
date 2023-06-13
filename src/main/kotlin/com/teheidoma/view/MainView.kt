package com.teheidoma.view

import com.teheidoma.CipherView
import tornadofx.*

class MainView : View("JWE encoder/decoder") {


    override val root = tabpane {
        tab<CipherView>()
        tab<KeyView>()
        setPrefSize(400.0, 300.0)
    }
}
