import { Editor } from '@tiptap/core';
import React from 'react';
import { Editor as ExtendedEditor } from './Editor.js';
export interface ReactRendererOptions {
    /**
     * The editor instance.
     * @type {Editor}
     */
    editor: Editor;
    /**
     * The props for the component.
     * @type {Record<string, any>}
     * @default {}
     */
    props?: Record<string, any>;
    /**
     * The tag name of the element.
     * @type {string}
     * @default 'div'
     */
    as?: string;
    /**
     * The class name of the element.
     * @type {string}
     * @default ''
     * @example 'foo bar'
     */
    className?: string;
    /**
     * The attributes of the element.
     * @type {Record<string, string>}
     * @default {}
     * @example { 'data-foo': 'bar' }
     */
    attrs?: Record<string, string>;
}
declare type ComponentType<R, P> = React.ComponentClass<P> | React.FunctionComponent<P> | React.ForwardRefExoticComponent<React.PropsWithoutRef<P> & React.RefAttributes<R>>;
/**
 * The ReactRenderer class. It's responsible for rendering React components inside the editor.
 * @example
 * new ReactRenderer(MyComponent, {
 *   editor,
 *   props: {
 *     foo: 'bar',
 *   },
 *   as: 'span',
 * })
*/
export declare class ReactRenderer<R = unknown, P = unknown> {
    id: string;
    editor: ExtendedEditor;
    component: any;
    element: Element;
    props: Record<string, any>;
    reactElement: React.ReactNode;
    ref: R | null;
    constructor(component: ComponentType<R, P>, { editor, props, as, className, attrs, }: ReactRendererOptions);
    render(): void;
    updateProps(props?: Record<string, any>): void;
    destroy(): void;
}
export {};
