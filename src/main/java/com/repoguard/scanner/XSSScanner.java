package com.repoguard.scanner;

import com.github.javaparser.StaticJavaParser;
import com.github.javaparser.ast.CompilationUnit;
import com.github.javaparser.ast.expr.BinaryExpr;
import com.github.javaparser.ast.expr.MethodCallExpr;
import com.github.javaparser.ast.expr.StringLiteralExpr;
import com.github.javaparser.ast.visitor.VoidVisitorAdapter;
import com.repoguard.model.Severity;
import com.repoguard.model.Vulnerability;
import org.springframework.stereotype.Component;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

@Component
public class XSSScanner {

    public List<Vulnerability> scan(List<File> javaFiles) {
        List<Vulnerability> vulnerabilities = new ArrayList<>();

        for (File file : javaFiles) {
            try {
                CompilationUnit cu = StaticJavaParser.parse(file);
                
                cu.accept(new VoidVisitorAdapter<List<Vulnerability>>() {
                    
                    @Override
                    public void visit(MethodCallExpr n, List<Vulnerability> arg) {
                        super.visit(n, arg);
                        String methodName = n.getNameAsString();
                        
                        // Check for response.getWriter().print(...) or out.println(...)
                        if (methodName.equals("print") || methodName.equals("println") || methodName.equals("write")) {
                            if (n.getScope().isPresent()) {
                                String scopeStr = n.getScope().get().toString();
                                if (scopeStr.contains("getWriter") || scopeStr.equals("out") || scopeStr.equals("response")) {
                                    // If argument is not just a hardcoded safe string, flag it
                                    if (n.getArguments().isNonEmpty() && !(n.getArgument(0) instanceof StringLiteralExpr)) {
                                        arg.add(new Vulnerability(
                                                "XSS",
                                                Severity.HIGH,
                                                file.getName(),
                                                n.getBegin().isPresent() ? n.getBegin().get().line : 0,
                                                "AST Detection: Dynamic input written directly to HTTP response.",
                                                "Escape user input using OWASP Java Encoder or HtmlUtils.htmlEscape()."
                                        ));
                                    }
                                }
                            }
                        }
                    }

                    @Override
                    public void visit(BinaryExpr n, List<Vulnerability> arg) {
                        super.visit(n, arg);
                        // Check for HTML concatenation: "<div>" + userInput
                        if (n.getOperator() == BinaryExpr.Operator.PLUS) {
                            boolean hasHtml = n.findAll(StringLiteralExpr.class).stream()
                                    .map(StringLiteralExpr::getValue)
                                    .anyMatch(val -> val.matches(".*<[a-zA-Z]+.*>.*")); // Simple HTML tag regex within a literal
                            
                            // If it has HTML and is concatenated with something else
                            if (hasHtml && !(n.getLeft() instanceof StringLiteralExpr && n.getRight() instanceof StringLiteralExpr)) {
                                arg.add(new Vulnerability(
                                        "XSS",
                                        Severity.MEDIUM,
                                        file.getName(),
                                        n.getBegin().isPresent() ? n.getBegin().get().line : 0,
                                        "AST Detection: HTML built via string concatenation with variables.",
                                        "Use a templating engine (Thymeleaf, FreeMarker) or escape input."
                                ));
                            }
                        }
                    }
                }, vulnerabilities);

            } catch (Exception e) {
                System.out.println("Error parsing file with JavaParser: " + file.getName());
            }
        }

        return vulnerabilities;
    }
}
