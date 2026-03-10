package com.usehashmap.keyinspector

import com.intellij.DynamicBundle
import org.jetbrains.annotations.Nls
import org.jetbrains.annotations.PropertyKey
import java.util.function.Supplier

private const val BUNDLE = "messages.KeyInspectorBundle"

internal object KeyInspectorBundle {
    private val instance = DynamicBundle(KeyInspectorBundle::class.java, BUNDLE)

    @JvmStatic
    fun message(
        @PropertyKey(resourceBundle = BUNDLE) key: String,
        vararg params: Any?
    ): @Nls String = instance.getMessage(key, *params)

    @JvmStatic
    fun lazyMessage(
        @PropertyKey(resourceBundle = BUNDLE) key: String,
        vararg params: Any?
    ): Supplier<@Nls String> = instance.getLazyMessage(key, *params)
}
